import logging
from socket import timeout
import time

from genie.abstract import Lookup
from genie.utils.timeout import Timeout
from genie.libs import conf, ops, sdk, parser
from genie.libs.parser.nxos.show_vpc import ShowVpc
from genie.libs.sdk.apis.execute import execute_copy_run_to_start
from pyats import aetest
from unicon.core.errors import SubCommandFailure
from unicon.eal.dialogs import Statement, Dialog
from lib import nxtest
from pyats.topology import loader
from genie.libs.clean.recovery.dialogs import RommonDialog as CommonRommonDialog
from lib.triggers.issu.issu import TriggerIssu

LOG = logging.getLogger()

class ReloadUp(nxtest.Testcase):
    @aetest.test
    def reload_bring_up(self, testbed, steps, device_dut, trigger_wait_time):
        for node in device_dut:
            uut = testbed.devices[node]
            loader_dialog = Dialog([
                Statement(pattern=r'^.*(Username|login): ?$',
                          action='sendline(admin)',
                          args=None,
                          loop_continue=True,
                          continue_timer=False),

                Statement(pattern=r'^.*Password: ?$',
                          action='sendline(nbv12345)',
                          args=None,
                          loop_continue=True,
                          continue_timer=False)])
            uut.execute('boot sanity.image', timeout=180, allow_state_change=True, reply=loader_dialog)
            time.sleep(int(30))
            uut.configure('boot nxos bootflash:sanity.image ; copy running-config startup-config', timeout=360)

        time.sleep(int(trigger_wait_time))

class Reload(nxtest.Testcase):
    @aetest.test
    def reload_trigger(self, testbed, device_dut, trigger_wait_time):
        for node in device_dut:
            interation = 0
            # modify testbed object
            testbed.devices['uut'] = testbed.devices[node]
            uut = testbed.devices['uut']
            abstract = Lookup.from_device(
                uut,
                packages={
                    'sdk': sdk,
                    'conf': conf,
                    'ops': ops,
                    'parser': parser})
            execute_copy_run_to_start(uut)
            credentials = ['default']

            try:
                uut.reload(reload_command='reload\ny\n', prompt_recovery=True, reload_creds=credentials,
                    timeout=600)
            except Exception as e:
                uut.disconnect()
                uut.destroy()
                LOG.error(e)

            time.sleep(int(trigger_wait_time))