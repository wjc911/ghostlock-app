#include "route/result_stack_route.h"

#include <cassert>
#include <cerrno>
#include <fcntl.h>
#include <type_traits>
#include <unistd.h>

using namespace ghostlock;

int32_t main(void) {
    race::PiRace race;
    assert(race.reset(0, 0, 1));
    memory::WriteRequest request{};
    profile::ResultStackLayout layout = {.waiter_shift = 14, .compact_waiter = 0};
    const profile::TargetProfile profile{};
    const std::array<int32_t, 3> no_stdio = {-1, -1, -1};

    route::result_stack::ResultStackRoute context(
        &race, &request, profile, layout, no_stdio);
    assert(context.race == &race && context.request == &request);
    assert(&context.profile == &profile);
    assert(context.layout.waiter_shift == 14);
    assert(!context.ready_fd.valid() && !context.peer_fd.valid());
    assert(context.status.code == route::ROUTE_RETRYABLE);
    assert(!context.input_set.test(0));

    static_assert(!std::is_copy_constructible_v<route::result_stack::ResultStackRoute>);
    static_assert(!std::is_copy_assignable_v<route::result_stack::ResultStackRoute>);
    static_assert(std::is_move_constructible_v<route::result_stack::ResultStackRoute>);

    {
        route::result_stack::ResultStackRoute source(
            &race, &request, profile, layout, no_stdio);
        int32_t fds[2];
        assert(pipe(fds) == 0);
        source.ready_fd.reset(fds[0]);
        source.peer_fd.reset(fds[1]);
        source.selected_fds_installed = 1;
        source.owned_input_set.set(9);
        route::result_stack::ResultStackRoute moved(std::move(source));
        assert(moved.ready_fd.get() == fds[0]);
        assert(!source.ready_fd.valid());
        assert(moved.peer_fd.get() == fds[1]);
        assert(moved.selected_fds_installed == 1);
        moved.destroy();
        assert(fcntl(fds[0], F_GETFD) == -1 && errno == EBADF);
        assert(fcntl(fds[1], F_GETFD) == -1 && errno == EBADF);
    }

    {
        route::result_stack::ResultStackRoute stuck(
            &race, &request, profile, layout, no_stdio);
        int32_t fds[2];
        assert(pipe(fds) == 0);
        stuck.ready_fd.reset(fds[0]);
        stuck.peer_fd.reset(fds[1]);
        stuck.select_errno = 9;
        stuck.consumer_stuck = 1;
        stuck.destroy();
        assert(stuck.status.code == route::ROUTE_DIRTY_FAILURE);
        assert(stuck.status.step == 34);
        assert(stuck.status.error_number == 9);
        assert(fcntl(fds[0], F_GETFD) != -1);
        assert(fcntl(fds[1], F_GETFD) != -1);
        close(fds[0]);
        close(fds[1]);
    }

    context.disarm();
    context.destroy();
    assert(context.status.userspace_clean == 1);
    assert(context.status.kernel_disarmed == 1);
    assert(context.status.code == route::ROUTE_FALLBACK_SAFE);

    puts("result_stack_route_test: ok");
    return 0;
}
