#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise normal HTTP VM fork with a real Linux guest and serial commands."""
import http.client
import json
import os
from pathlib import Path
import re
import select
import signal
import socket
import subprocess
import sys
import time

binary, kernel, initramfs, directory = sys.argv[1:]
out = Path(directory).resolve()
out.mkdir(parents=True, exist_ok=True)
(out / "results.json").unlink(missing_ok=True)
parent_api, child_api = out / 'parent.api', out / 'child.api'
parent_serial, child_serial = out / 'parent.serial', out / 'child.serial'
disk = out / 'disk.raw'
with disk.open('wb') as f:
    f.write(b'fork-device-state')
    f.truncate(1024 * 1024)


def api(path, endpoint, body=None, method='PUT', expected=204):
    conn = http.client.HTTPConnection('localhost', timeout=5)
    conn.sock = socket.socket(socket.AF_UNIX)
    conn.sock.settimeout(5)
    conn.sock.connect(str(path))
    try:
        conn.request(method, '/api/v1/' + endpoint,
                     json.dumps(body) if body is not None else None)
        reply = conn.getresponse()
        data = reply.read()
        assert reply.status == expected, (endpoint, reply.status, data)
        return json.loads(data) if data else None
    finally:
        conn.close()


def wait_api(path, state=None):
    deadline = time.monotonic() + 40
    while time.monotonic() < deadline:
        try:
            result = api(path, 'vm.info' if state else 'vmm.ping',
                         method='GET', expected=200)
            if state is None or result['state'] == state:
                return result
        except (OSError, http.client.HTTPException, AssertionError):
            pass
        time.sleep(.05)
    raise AssertionError(f'API {path} did not reach {state}')


def wait_operation(path, operation_id, expected='Ready'):
    deadline = time.monotonic() + 40
    while time.monotonic() < deadline:
        try:
            operations = api(path, 'vm.fork-status', method='GET', expected=200)
        except (OSError, http.client.HTTPException, AssertionError):
            time.sleep(.02)
            continue
        op = next(op for op in operations if op['operation_id'] == operation_id)
        if op['state'] not in ('Accepted', 'Restoring'):
            assert op['state'] == expected, op
            return op
        time.sleep(.02)
    raise AssertionError(f'Operation {operation_id} did not finish')


class Serial:
    def __init__(self, path, name):
        self.sock = socket.socket(socket.AF_UNIX)
        self.sock.settimeout(5)
        self.sock.connect(str(path))
        self.text = ''
        self.log = (out / name).open('w')

    def wait(self, text, fresh=False):
        if fresh:
            self.text = ''
        deadline = time.monotonic() + 60
        while text not in self.text and time.monotonic() < deadline:
            if not select.select([self.sock], [], [], .2)[0]:
                continue
            data = self.sock.recv(65536)
            assert data, 'serial disconnected before ' + text
            data = data.decode(errors='replace')
            self.log.write(data)
            self.log.flush()
            self.text += data
        assert text in self.text, (text, self.text[-2000:])

    def close(self):
        self.sock.close()
        self.log.close()


def pss(pid, ranges):
    total, inside = 0, False
    smaps = Path(f'/proc/{pid}/smaps').read_text()
    (out / f'{pid}.smaps').write_text(smaps)
    for line in smaps.splitlines():
        match = re.match(r'([0-9a-f]+)-([0-9a-f]+) ', line)
        if match:
            a, b = [int(x, 16) for x in match.groups()]
            inside = any(a >= start and b <= end for start, end in ranges)
        elif inside and line.startswith('Pss:'):
            total += int(line.split()[1])
    return total


# Normal seccomp configuration must reject fork without disturbing the API.
disabled_api = out / 'disabled.api'
with (out / 'disabled.log').open('w') as log:
    disabled = subprocess.Popen([binary, '--api-socket', str(disabled_api)],
                                stdout=log, stderr=log)
    try:
        wait_api(disabled_api)
        api(disabled_api, 'vm.fork', {'child_api_socket': str(child_api),
                                     'child_serial_socket': str(child_serial)}, expected=400)
        wait_api(disabled_api)
        api(disabled_api, 'vmm.shutdown', expected=200)
        assert disabled.wait(timeout=15) == 0
    finally:
        if disabled.poll() is None:
            disabled.kill()
        disabled.wait()


def resources(pid):
    descriptors = {}
    for fd in Path(f'/proc/{pid}/fd').iterdir():
        try: descriptors[fd.name] = os.readlink(fd)
        except FileNotFoundError: pass
    (out / f'fds-{pid}-{time.monotonic_ns()}.json').write_text(json.dumps(descriptors, indent=2))
    roles = {}
    for task in Path(f'/proc/{pid}/task').iterdir():
        status = dict(line.split(':', 1) for line in (task / 'status').read_text().splitlines() if ':' in line)
        if status.get('Kthread', '0').strip() == '1':
            continue
        assert status['Seccomp'].strip() == '2', status
        roles.setdefault(status['Name'].strip(), []).append(int(status['Seccomp_filters']))
    return {'threads': len(list(Path(f'/proc/{pid}/task').iterdir())),
            'fds': len(list(Path(f'/proc/{pid}/fd').iterdir())),
            'filters': {name: sorted(values) for name, values in roles.items()}}


with (out / 'vmm.log').open('w') as log:
    proc = subprocess.Popen([binary, '--api-socket', str(parent_api), '--enable-fork'],
                            stdout=log, stderr=log, start_new_session=True)
    serials = []
    try:
        wait_api(parent_api)
        config = {
            'cpus': {'boot_vcpus': 2, 'max_vcpus': 2},
            'memory': {'size': 256 * 1024 * 1024, 'shared': False, 'thp': False},
            'payload': {'kernel': kernel, 'initramfs': initramfs,
                        'cmdline': 'console=ttyS0 panic=-1 rdinit=/init'},
            'disks': [{'path': os.environ.get('NATIVE_DISK_SOCKET', str(disk)), 'readonly': True, 'image_type': 'Raw'}],
            'serial': {'mode': 'Socket', 'socket': str(parent_serial)},
            'console': {'mode': 'Off'},
        }
        api(parent_api, 'vm.create', config)
        seed = Serial(parent_serial, 'seed.log')
        serials.append(seed)
        api(parent_api, 'vm.boot')
        seed.wait('FORK_READY ')
        # Failures must leave the running source intact.
        api(parent_api, 'vm.fork', {'child_api_socket': str(parent_api),
                                  'child_serial_socket': str(child_serial)}, expected=400)
        api(parent_api, 'vm.fork', {'child_api_socket': str(child_api),
                                  'child_serial_socket': str(child_api)}, expected=400)
        api(parent_api, 'vm.fork', {'child_api_socket': str(child_api),
                                  'child_serial_socket': str(child_api) + '.lock'}, expected=400)
        api(parent_api, 'vm.fork', {'child_api_socket': str(child_api),
                                  'child_serial_socket': str(child_serial), 'unexpected': True}, expected=400)
        assert api(parent_api, 'vm.info', method='GET', expected=200)['state'] == 'Running'
        first_request_start = time.monotonic()
        accepted = api(parent_api, 'vm.fork', {'child_api_socket': str(child_api),
                                  'child_serial_socket': str(child_serial)}, expected=200)
        first_op = wait_operation(parent_api, accepted['operation_id'])
        seed.close()
        serials.remove(seed)
        wait_api(parent_api, 'Paused')
        wait_api(child_api, 'Paused')
        text = (out / 'vmm.log').read_text()
        assert 'boundary threads=1' in text, text
        match = re.search(r'child_pid=(\d+) combined_ram_pss_kib=(\d+) baseline_kib=(\d+)', text)
        assert match, text
        child_pid, combined, baseline = map(int, match.groups())
        assert baseline > 32 * 1024 and abs(combined - baseline) <= 16, (combined, baseline)
        ranges = [(int(a, 16), int(b, 16)) for a, b in
                  re.findall(r'ram_range=([0-9a-f]+)-([0-9a-f]+)', text)]
        parent = Serial(parent_serial, 'parent.log')
        child = Serial(child_serial, 'child.log')
        serials.extend([parent, child])
        api(parent_api, 'vm.resume')
        parent.sock.sendall(b'20\n')
        parent.wait('FORK_RESULT initial=10 value=20')
        assert 'FORK_DISK_OK value=20' in parent.text
        # The child has not run while the parent changed the original KVM page.
        assert api(child_api, 'vm.info', method='GET', expected=200)['state'] == 'Paused'
        api(child_api, 'vm.resume')
        child.sock.sendall(b'30\n')
        child.wait('FORK_RESULT initial=10 value=30')
        first_request_to_child_result_ms = (time.monotonic()-first_request_start)*1000
        assert 'FORK_DISK_OK value=30' in child.text
        parent.wait('FORK_ALIVE value=20', fresh=True)
        child.wait('FORK_ALIVE value=30', fresh=True)
        api(parent_api, 'vm.pause')
        api(child_api, 'vm.pause')
        parent_pss, child_pss = pss(proc.pid, ranges), pss(child_pid, ranges)
        assert 0 < parent_pss < baseline * .75, (parent_pss, baseline)
        assert 0 < child_pss < baseline * .75, (child_pss, baseline)
        # Verify freshly created API eventfds and signal workers are independent.
        api(parent_api, 'vm.resume')
        parent.wait('FORK_ALIVE value=20', fresh=True)
        assert api(child_api, 'vm.info', method='GET', expected=200)['state'] == 'Paused'
        api(child_api, 'vm.resume')
        api(parent_api, 'vmm.shutdown', expected=200)
        assert proc.wait(timeout=15) == 0
        child.wait('FORK_ALIVE value=30', fresh=True)
        assert api(child_api, 'vm.info', method='GET', expected=200)['state'] == 'Running'
        # A rebuilt child must itself be able to fork, with new workers,
        # listeners and signal registrations on every generation.
        grand_api, grand_serial = out / 'grand.api', out / 'grand.serial'
        accepted = api(child_api, 'vm.fork', {'child_api_socket': str(grand_api),
                                 'child_serial_socket': str(grand_serial)}, expected=200)
        second_op = wait_operation(child_api, accepted['operation_id'])
        child.close()
        serials.remove(child)
        wait_api(child_api, 'Paused')
        wait_api(grand_api, 'Paused')
        child = Serial(child_serial, 'child-second.log')
        grand = Serial(grand_serial, 'grand.log')
        serials.extend([child, grand])
        api(child_api, 'vm.resume')
        api(grand_api, 'vm.resume')
        child.wait('FORK_ALIVE value=30')
        grand.wait('FORK_ALIVE value=30')
        text = (out / 'vmm.log').read_text()
        boundaries = re.findall(r'child_pid=(\d+) combined_ram_pss_kib=(\d+) baseline_kib=(\d+)', text)
        assert len(boundaries) == 2, text
        grand_pid, second_combined, second_baseline = map(int, boundaries[1])
        assert abs(second_combined - second_baseline) <= 16
        os.kill(child_pid, signal.SIGTERM)
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline and child_api.exists():
            time.sleep(.05)
        assert not child_api.exists(), 'rebuilt child signal handler did not shut down'
        grand.wait('FORK_ALIVE value=30', fresh=True)
        # Post-acceptance child startup failure, using a real unbindable path.
        failed = api(grand_api, 'vm.fork', {
            'child_api_socket': f'/proc/ch-fork-{grand_pid}.api',
            'child_serial_socket': str(out / 'failed.serial')}, expected=200)
        grand.close()
        serials.remove(grand)
        failed = wait_operation(grand_api, failed['operation_id'], 'Failed')
        assert failed['error'] and failed['child_pid']
        wait_api(grand_api, 'Running')
        grand = Serial(grand_serial, 'grand-recovered.log')
        serials.append(grand)
        grand.wait('FORK_ALIVE value=30')
        api(grand_api, 'vm.pause')
        restore_failed = api(grand_api, 'vm.fork', {
            'child_api_socket': str(out / 'restore-failed.api'),
            'child_serial_socket': f'/proc/ch-fork-{grand_pid}.serial'}, expected=200)
        grand.close()
        serials.remove(grand)
        restore_failed = wait_operation(grand_api, restore_failed['operation_id'], 'Failed')
        assert restore_failed['error']
        wait_api(grand_api, 'Paused')
        grand = Serial(grand_serial, 'grand-recovered-paused.log')
        serials.append(grand)
        api(grand_api, 'vm.resume')
        grand.wait('FORK_ALIVE value=30')
        # Repeated reconstruction must not accumulate descriptors or filters.
        baseline_resources = resources(grand_pid)
        stress_ops = []
        concurrent_statuses = []
        for iteration in range(10):
            branch_api = out / f'stress{iteration}.api'
            branch_serial = out / f'stress{iteration}.serial'
            # Submit two fork requests on existing connections before reading
            # either response. Only one may be accepted by this runtime.
            connections = []
            for request in [
                {'child_api_socket': str(branch_api), 'child_serial_socket': str(branch_serial)},
                {'child_api_socket': str(out / f'contender{iteration}.api'),
                 'child_serial_socket': str(out / f'contender{iteration}.serial')},
            ]:
                conn = http.client.HTTPConnection('localhost', timeout=5)
                conn.sock = socket.socket(socket.AF_UNIX)
                conn.sock.settimeout(5)
                conn.sock.connect(str(grand_api))
                connections.append((conn, request))
            for conn, request in connections:
                conn.request('PUT', '/api/v1/vm.fork', json.dumps(request))
            accepted_requests, statuses = [], []
            for conn, _ in connections:
                try:
                    response = conn.getresponse()
                    data = response.read()
                    statuses.append(response.status)
                    if response.status == 200:
                        accepted_requests.append(json.loads(data))
                except (OSError, http.client.HTTPException):
                    statuses.append('disconnected')
                finally:
                    conn.close()
            assert len(accepted_requests) == 1, (accepted_requests, statuses)
            assert all(status in (200, 409, 503, 'disconnected') for status in statuses), statuses
            accepted = accepted_requests[0]
            branch_api = Path(accepted['child_api_socket'])
            concurrent_statuses.append(statuses)
            grand.close()
            serials.remove(grand)
            operation = wait_operation(grand_api, accepted['operation_id'])
            stress_ops.append(operation)
            grand = Serial(grand_serial, f'grand-stress{iteration}.log')
            serials.append(grand)
            api(grand_api, 'vm.resume')
            grand.wait('FORK_ALIVE value=30')
            if iteration % 2:
                os.kill(operation['child_pid'], signal.SIGKILL)
            else:
                api(branch_api, 'vmm.shutdown', expected=200)
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                ops = api(grand_api, 'vm.fork-status', method='GET', expected=200)
                if next(op for op in ops if op['operation_id'] == operation['operation_id'])['state'] == 'ChildExited':
                    break
                time.sleep(.02)
            else:
                raise AssertionError('child exit not reflected in operation status')
            current = resources(grand_pid)
            assert current == baseline_resources, (baseline_resources, current)
        api(grand_api, 'vmm.shutdown', expected=200)
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline and grand_api.exists():
            time.sleep(.05)
        assert not grand_api.exists(), 'grandchild HTTP shutdown did not complete'
        all_boundaries = re.findall(r'combined_ram_pss_kib=(\d+) baseline_kib=(\d+)', (out / 'vmm.log').read_text())
        assert len(all_boundaries) == 14, all_boundaries
        assert all(abs(int(combined) - int(baseline)) <= 16 for combined, baseline in all_boundaries)
        assert not list(out.rglob('memory.img'))
        result = {'native_disk_export': bool(os.environ.get('NATIVE_DISK_SOCKET')), 'request_to_child_result_ms': first_request_to_child_result_ms, 'parent_pid': proc.pid, 'child_pid': child_pid,
                  'fork_baseline_pss_kib': baseline, 'fork_combined_pss_kib': combined,
                  'running_parent_pss_kib': parent_pss, 'running_child_pss_kib': child_pss,
                  'grandchild_pid': grand_pid, 'operations': [first_op, second_op],
                  'failed_child': failed, 'failed_restore': restore_failed, 'stress_operations': stress_ops,
                  'stable_resources': baseline_resources, 'concurrent_request_statuses': concurrent_statuses,
                  'second_fork_baseline_pss_kib': second_baseline,
                  'second_fork_combined_pss_kib': second_combined,
                  'result': 'PASS: seccomp HTTP fork, Linux CoW, failure recovery, concurrent requests, 10 repetitions, stable resources'}
        (out / 'results.json').write_text(json.dumps(result, indent=2) + '\n')
        print(json.dumps(result, indent=2))
    finally:
        for serial in serials:
            serial.close()
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.wait()
