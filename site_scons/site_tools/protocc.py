# Pattern-matched from a C++ and Python version available here:
# http://www.scons.org/wiki/ProtocBuilder

"""protoc-c.py: protoc-c Builder for SCons

This Builder invokes protoc-c to generate C from a .proto file."""

__author__ = "Scott Stafford, Marti Bolivar"

import SCons.Action
import SCons.Builder
import SCons.Util

from SCons.Script import File, Dir

import os.path

protocc = 'protoc-c'

ProtocCAction = SCons.Action.Action('$PROTOCCCOM', '$PROTOCCCOMSTR')

def ProtocCEmitter(target, source, env):
    dirOfCallingSConscript = Dir('.').srcnode()
    env.Prepend(PROTOCPROTOPATH = dirOfCallingSConscript.path)

    source_with_corrected_path = []
    for src in source:
        commonprefix = os.path.commonprefix([dirOfCallingSConscript.path,
                                             src.srcnode().path])
        if len(commonprefix) > 0:
            slice_start = len(commonprefix + os.sep)
        else:
            slice_start = 0
        source_with_corrected_path.append(src.srcnode().path[slice_start:])

    source = source_with_corrected_path

    for src in source:
        modulename = os.path.splitext(src)[0]
        if env['PROTOCCOUTDIR']:
            base = os.path.join(env['PROTOCCOUTDIR'] , modulename)
            target.extend([base + '.pb-c.c', base + '.pb-c.h'])

    #~ print "PROTOC SOURCE:", [str(s) for s in source]
    #~ print "PROTOC TARGET:", [str(s) for s in target]

    return target, source

ProtocCBuilder = SCons.Builder.Builder(action=ProtocCAction,
                                       emitter=ProtocCEmitter,
                                       srcsuffix='$PROTOCCSRCSUFFIX')

def generate(env):
    """Add Builders and construction variables for protoc-c to an
    Environment."""
    try:
        bld = env['BUILDERS']['ProtocC']
    except KeyError:
        bld = ProtocCBuilder
        env['BUILDERS']['ProtocC'] = bld

    env['PROTOCC'] = env.Detect(protocc) or protocc
    env['PROTOCCFLAGS'] = SCons.Util.CLVar('')
    env['PROTOPATH'] = SCons.Util.CLVar('')
    env['PROTOCCCOM'] = '$PROTOCC ${["-I%s" % x for x in PROTOPATH]} $PROTOCCFLAGS --c_out=$PROTOCCOUTDIR ${SOURCES}'
    env['PROTOCCOUTDIR'] = '${SOURCE.dir}'
    env['PROTOSRCSUFFIX']  = '.proto'

def exists(env):
    return env.Detect(protocc)

