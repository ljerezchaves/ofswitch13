# -*- Mode: python; py-indent-offset: 4; indent-tabs-mode: nil; coding: utf-8; -*-

import os
from waflib import Logs, Options
from waflib.Errors import WafError

# This OFSwitch13 version is compatible with ns-3.31 or later.
def check_version_compatibility(version):
    base = (3, 31)
    try:
        comp = tuple(map(int, (version.split("."))))
        return comp >= base
    except:
        if version == '3-dev':
            return True
        else:
            return False

def options(opt):
    opt.add_option('--with-ofswitch13',
        help=('Explicit path to the ofsoftswitch13 directory for ns-3 OpenFlow 1.3 integration support. By default, the configuration script will check for the lib/ofsoftswitch13 directory.'),
        default='', dest='with_ofswitch13')

def configure(conf):
    # Check for OFSwitch13 and ns-3 version compatibility
    if check_version_compatibility(conf.env.VERSION):
        conf.msg ("Checking for OpenFlow 1.3 compatibility", "ok")
    else:
        conf.msg ("Checking for OpenFlow 1.3 compatibility", "no", color = 'YELLOW')
        conf.report_optional_feature("ofswitch13", "NS-3 OpenFlow 1.3 integration", False, "Incompatible ns-3 release")
        conf.env.MODULES_NOT_BUILT.append('ofswitch13')
        return

    # Check for the explicit ofsoftswitch13 given location (using --with-ofswitch13)
    if Options.options.with_ofswitch13:
        if os.path.isdir(Options.options.with_ofswitch13):
            conf.msg("Checking for ofsoftswitch13 location", ("%s (given)" % Options.options.with_ofswitch13))
            conf.env.WITH_OFSWITCH13 = os.path.abspath(Options.options.with_ofswitch13)
        else:
            conf.msg ("Checking for ofsoftswitch13 location", ("not found [%s (given)]"  % Options.options.with_ofswitch13), color = 'YELLOW')
            conf.report_optional_feature("ofswitch13", "NS-3 OpenFlow 1.3 integration", False, "ofsoftswitch13 given location not found (see option --with-ofswitch13)")
            conf.env.MODULES_NOT_BUILT.append('ofswitch13')
            return

    # No explicit ofsoftswitch13 given location. Check for the default location (./lib/ofsoftswitch13/)
    else:
        contrib_dir = os.path.join('contrib', 'ofswitch13', 'lib', 'ofsoftswitch13')
        if os.path.isdir(contrib_dir):
            conf.msg("Checking for ofsoftswitch13 location", ("%s (guessed)" % contrib_dir))
            conf.env.WITH_OFSWITCH13 = os.path.abspath(contrib_dir)
        else:
            src_dir = os.path.join('src', 'ofswitch13', 'lib', 'ofsoftswitch13')
            if os.path.isdir(src_dir):
                conf.msg("Checking for ofsoftswitch13 location", ("%s (guessed)" % src_dir))
                conf.env.WITH_OFSWITCH13 = os.path.abspath(src_dir)
            else:
                conf.msg("Checking for ofsoftswitch13 location", "not found [lib/ofsoftswitch13 (guessed)]", color = 'YELLOW')
                conf.report_optional_feature("ofswitch13", "NS-3 OpenFlow 1.3 integration", False, "ofsoftswitch13 default location not found (see option --with-ofswitch13)")
                conf.env.MODULES_NOT_BUILT.append('ofswitch13')
                return

    # Checking for required libraries
    conf.env.OFSWITCH13 = conf.check(mandatory=False, lib='ns3ofswitch13', libpath=os.path.abspath(os.path.join(conf.env.WITH_OFSWITCH13,'udatapath')))
    conf.report_optional_feature("ofswitch13", "NS-3 OpenFlow 1.3 integration", conf.env.OFSWITCH13, "Required libraries not found")
    if not conf.env.OFSWITCH13:
        conf.env.MODULES_NOT_BUILT.append('ofswitch13')
        return

    # Configuring module environment
    conf.env.DEFINES_OFSWITCH13 = ['NS3_OFSWITCH13']
    conf.env.INCLUDES_OFSWITCH13 = [
            os.path.abspath(conf.env.WITH_OFSWITCH13),
            os.path.abspath(os.path.join(conf.env.WITH_OFSWITCH13,'include')),
            os.path.abspath(os.path.join(conf.env.WITH_OFSWITCH13,'lib')),
            os.path.abspath(os.path.join(conf.env.WITH_OFSWITCH13,'oflib')),
            os.path.abspath(os.path.join(conf.env.WITH_OFSWITCH13,'oflib-exp')),
            os.path.abspath(os.path.join(conf.env.WITH_OFSWITCH13,'secchan')),
            os.path.abspath(os.path.join(conf.env.WITH_OFSWITCH13,'udatapath'))];
    conf.env.LIB_OFSWITCH13 = ['dl', 'ns3ofswitch13']
    conf.env.LIBPATH_OFSWITCH13 = [os.path.abspath(os.path.join(conf.env.WITH_OFSWITCH13,'udatapath'))]


def build(bld):
    # Don't do anything for this module if ofswitch13's not enabled.
    if 'ofswitch13' in bld.env.MODULES_NOT_BUILT:
        return

    module = bld.create_ns3_module('ofswitch13', ['core', 'network', 'internet', 'csma', 'point-to-point', 'virtual-net-device', 'applications'])
    module.source = [
        'model/ofswitch13-controller.cc',
        'model/ofswitch13-device.cc',
        'model/ofswitch13-interface.cc',
        'model/ofswitch13-learning-controller.cc',
        'model/ofswitch13-queue.cc',
        'model/ofswitch13-priority-queue.cc',
        'model/ofswitch13-port.cc',
        'model/ofswitch13-socket-handler.cc',
        'model/queue-tag.cc',
        'model/tunnel-id-tag.cc',
        'helper/ofswitch13-device-container.cc',
        'helper/ofswitch13-external-helper.cc',
        'helper/ofswitch13-helper.cc',
        'helper/ofswitch13-internal-helper.cc',
        'helper/ofswitch13-stats-calculator.cc'
        ]
    module.use.extend('OFSWITCH13'.split())

    headers = bld(features='ns3header')
    headers.module = 'ofswitch13'
    headers.source = [
        'model/ofswitch13-controller.h',
        'model/ofswitch13-device.h',
        'model/ofswitch13-interface.h',
        'model/ofswitch13-learning-controller.h',
        'model/ofswitch13-queue.h',
        'model/ofswitch13-priority-queue.h',
        'model/ofswitch13-port.h',
        'model/ofswitch13-socket-handler.h',
        'model/queue-tag.h',
        'model/tunnel-id-tag.h',
        'helper/ofswitch13-device-container.h',
        'helper/ofswitch13-external-helper.h',
        'helper/ofswitch13-helper.h',
        'helper/ofswitch13-internal-helper.h',
        'helper/ofswitch13-stats-calculator.h'
        ]

    if bld.env['ENABLE_EXAMPLES']:
        bld.recurse('examples')

