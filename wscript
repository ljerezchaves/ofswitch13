# -*- Mode: python; py-indent-offset: 4; indent-tabs-mode: nil; coding: utf-8; -*-

import os
from waflib import Logs, Options
from waflib.Errors import WafError


def options(opt):
    opt.add_option('--with-ofswitch13',
        help=('Path to ofsoftswitch13 for NS-3 OpenFlow 1.3 Integration support'),
        default='', dest='with_ofswitch13')


def configure(conf):
    if not Options.options.with_ofswitch13:
        conf.msg("Checking for OpenFlow 1.3 location", False)
        conf.report_optional_feature("ofswitch13", "NS-3 OpenFlow 1.3 Integration", False,
                                     "ofswitch13 not enabled (see option --with-ofswitch13)")
        conf.env.MODULES_NOT_BUILT.append('ofswitch13')
        return

    if os.path.isdir(Options.options.with_ofswitch13):
            conf.msg("Checking for OpenFlow 1.3 location", ("%s (given)" % Options.options.with_ofswitch13))
            conf.env.WITH_OFSWITCH13 = os.path.abspath(Options.options.with_ofswitch13)
        
    if not conf.env.WITH_OFSWITCH13:
        conf.msg("Checking for OpenFlow 1.3 location", False)
        conf.report_optional_feature("ofswitch13", "NS-3 OpenFlow 1.3 Integration", False,
                                     "OpenFlow 1.3 given location not found (see option --with-ofswitch13)")
        conf.env.MODULES_NOT_BUILT.append('ofswitch13')
        return 


    # Checking for libraries and configuring paths
    conf.env.DL = conf.check(mandatory=True, lib='dl', define_name='DL', uselib_store='DL')
    conf.env.NBEE = conf.check(mandatory=True, lib='nbee', define_name='NBEE', uselib_store='NBEE')
    conf.env.OFSWITCH13 = conf.check(mandatory=True, lib='ns3ofswitch13', use='NBEE',
            libpath=os.path.abspath(os.path.join(conf.env['WITH_OFSWITCH13'],'udatapath')))
     
    conf.env.DEFINES_OFSWITCH13 = ['NS3_OFSWITCH13']
    conf.env.INCLUDES_OFSWITCH13 = [
            os.path.abspath(conf.env['WITH_OFSWITCH13']),
            os.path.abspath(os.path.join(conf.env['WITH_OFSWITCH13'],'include')),
            os.path.abspath(os.path.join(conf.env['WITH_OFSWITCH13'],'lib')),
            os.path.abspath(os.path.join(conf.env['WITH_OFSWITCH13'],'oflib')),
            os.path.abspath(os.path.join(conf.env['WITH_OFSWITCH13'],'oflib-exp')),
            os.path.abspath(os.path.join(conf.env['WITH_OFSWITCH13'],'secchan')),
            os.path.abspath(os.path.join(conf.env['WITH_OFSWITCH13'],'udatapath'))];
    conf.env.LIB_OFSWITCH13 = ['dl', 'nbee', 'ns3ofswitch13']
    conf.env.LIBPATH_OFSWITCH13 = [os.path.abspath(os.path.join(conf.env['WITH_OFSWITCH13'],'udatapath'))]
   
    conf.report_optional_feature("ofswitch13", "NS-3 OpenFlow 1.3 Integration",
            conf.env.OFSWITCH13, "ns3ofswitch13 library not found")
    
    if not conf.env.OFSWITCH13:
        conf.env.MODULES_NOT_BUILT.append('ofswitch13')
   

def build(bld):
    # Don't do anything for this module if ofswitch13's not enabled.
    if 'ofswitch13' in bld.env.MODULES_NOT_BUILT:
        return

    module = bld.create_ns3_module('ofswitch13', ['internet', 'bridge', 'mpi', 'network', 'core', 'stats', 'csma', 'point-to-point', 'applications'])
    module.source = [
        'model/ofswitch13-interface.cc',
        'model/ofswitch13-port.cc',
        'model/ofswitch13-device.cc',
        'model/ofswitch13-controller.cc',
        'model/ofswitch13-learning-controller.cc',
        'model/ofswitch13-queue.cc',
        'model/queue-tag.cc',
        'helper/ofswitch13-helper.cc',
        'helper/ofswitch13-device-container.cc'
        ]
    module.use.extend('OFSWITCH13'.split())

    module_test = bld.create_ns3_module_test_library('ofswitch13')
    module_test.source = [
        'test/ofswitch13-simple-transmission.cc',
        'test/ofswitch13-dual-controller.cc'
        ]
    module_test.use.extend('OFSWITCH13'.split())

    headers = bld(features='ns3header')
    headers.module = 'ofswitch13'
    headers.source = [
        'model/ofswitch13-interface.h',
        'model/ofswitch13-port.h',
        'model/ofswitch13-device.h',
        'model/ofswitch13-controller.h',
        'model/ofswitch13-learning-controller.h',
        'model/ofswitch13-queue.h',
        'model/queue-tag.h',
        'helper/ofswitch13-helper.h',
        'helper/ofswitch13-device-container.h'
        ]

    if bld.env['ENABLE_EXAMPLES']:
        bld.recurse('examples')


