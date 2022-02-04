# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from __future__ import division, absolute_import, with_statement, print_function, unicode_literals
from multiscanner.config import CONFIG

try:
    import pyclamd
except ImportError:
    print("pyclamd module not installed...")
    pyclamd = None

__author__ = 'Mike Long'
__license__ = "MPL 2.0"

DEFAULTCONF = {
    "ENABLED": True,
    "host" : "192.168.2.168"
    "port" : "3310"
}


def check(conf=DEFAULTCONF):
    if not conf['ENABLED']:
        return False
    if not pyclamd:
        return False
    return True


def _connect_clam(host,port):
    try:
        clamScanner = pyclamd.ClamdUnixSocket()
        clamScanner.ping()
        print("checking for unixsocket")
    except pyclamd.ConnectionError:
        clamScanner = pyclamd.ClamdNetworkSocket(host+":"+port)
        try:
            clamScanner.ping()
        except pyclamd.ConnectionError:
            raise ValueError("Could not connect to clamd server either by unix or network socket")
    return clamScanner


def scan(filelist, conf=DEFAULTCONF):
    results = []
    try:
        clamScanner = _connect_clam(conf['host'],conf['port'])
    except Exception as e:
        # TODO: log exception
        print("clamavscan ",e)
        return None

    # Scan each file from filelist for virus
    for f in filelist:
        output = clamScanner.scan_file(f)
        if output is None:
            continue

        if list(output.values())[0][0] == 'ERROR':
            with open(f, 'rb') as file_handle:
                try:
                    output = clamScanner.scan_stream(file_handle.read())
                except pyclamd.BufferTooLongError:
                    continue
                except Exception as e:
                    print(e)
                    clamScanner = _connect_clam()
                    output = clamScanner.scan_stream(file_handle.read())

        if output is None:
            continue

        if list(output.values())[0][0] == 'FOUND':
            results.append((f, list(output.values())[0][1]))
        elif list(output.values())[0][0] == 'ERROR':
            print('ClamAV: ERROR:', list(output.values())[0][1])

    # Set metadata tags
    metadata = {
        'Name': "ClamAV",
        'Type': "Antivirus",
        'Version': clamScanner.version()
    }

    return (results, metadata)
