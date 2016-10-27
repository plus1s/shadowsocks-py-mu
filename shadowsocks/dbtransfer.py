#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright 2015 mengskysama
# Copyright 2016 Howard Liu
# Copyright 2016 Plus1s
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import re
import json
import time
import pyrad
import config
import socket
import logging
import psycopg2

from datetime import datetime, timedelta
from shadowsocks.common import U, D


def transform_datetime(data):
    datetime_format = '%Y-%m-%d %H:%M:%S+00'
    if isinstance(data, datetime):
        return data.strftime(datetime_format)
    elif isinstance(data, basestring) and re.match(r'^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\+00', data):
        return datetime.strptime(data, datetime_format)
    else:
        logging.warn('WARN: cannot parse datetime {}'.format(data))


class DbTransfer(object):
    def __init__(self):
        pass

    @staticmethod
    def send_command(cmd):
        data = ''
        try:
            cli = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            cli.settimeout(2)
            cli.sendto(cmd, ('%s' % config.MANAGE_BIND_IP, config.MANAGE_PORT))
            data, addr = cli.recvfrom(1500)
            cli.close()
            # TODO: bad way solve timed out
            time.sleep(0.05)
        except Exception as e:
            if config.SS_VERBOSE:
                import traceback
                traceback.print_exc()
            logging.warn('Exception thrown when sending command: %s' % e)
        return data

    @staticmethod
    def send_radius_packet(req):
        try:
            radclient = DbTransfer.get_radclient()
            radclient.SendPacket(req)
        except pyrad.client.Timeout:
            logging.warn('RADIUS: server does not reply')
        except socket.error as error:
            logging.warn('RADIUS: network error: {}'.format(error[1]))

    @staticmethod
    def send_radius_acct(status_type, username, port, sessionid,
                         sessiontime=0, inputoctets=0, outputoctets=0, terminatecause='Idle-Timeout'):
        radclient = DbTransfer.get_radclient()
        req = radclient.CreateAcctPacket(User_Name=username)
        req.update({
            'Acct-Session-Id': sessionid,
            'Called-Station-Id': port,
            'Calling-Station-Id': config.NODE_NAME,
        })
        if status_type == 'Start':
            req.update({
                'NAS-IP-Address': config.RADIUS_NAS_IP,
                'NAS-Identifier': 'ShadowSocks',
            })
        elif status_type in ('Interim-Update', 'Stop'):
            req.update({
                'Acct-Session-Time': sessiontime,
                'Acct-Input-Octets': inputoctets,
                'Acct-Output-Octets': outputoctets,
            })
            if status_type == 'Stop':
                req.update({
                    'Acct-Terminate-Cause': terminatecause,
                })
        DbTransfer.send_radius_packet(req)

    @staticmethod
    def get_servers_transfer():
        dt_transfer = {}
        cli = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        cli.settimeout(2)
        cli.sendto('transfer: {}', (config.MANAGE_BIND_IP, config.MANAGE_PORT))
        while True:
            data, addr = cli.recvfrom(1500)
            if data == 'e':
                break
            data = json.loads(data)
            # print data
            dt_transfer.update(data)
        cli.close()
        return dt_transfer

    @staticmethod
    def get_db_conn():
        return psycopg2.connect(host=config.DB_HOST, port=config.DB_PORT, user=config.DB_USER,
                                password=config.DB_PASS, database=config.DB_NAME)

    @staticmethod
    def get_radclient():
        return pyrad.Client(server=config.RADIUS_SERVER, secret=config.RADIUS_SECRET,
                            dict=pyrad.dictionary.Dictionary(config.RADIUS_DICTIONARY))

    @staticmethod
    def push_all_users(users, accts):
        dt_transfer = DbTransfer.get_servers_transfer()
        now = datetime.utcnow()

        for port in dt_transfer:
            attrs = {'port': port}
            if port in accts:
                acct = accts[port]
                seconds_since_start = int(
                    now - transform_datetime(acct['Acct-Start-Time']).strftime('%s')
                )
                seconds_since_last_update = int(
                    now - transform_datetime(acct['Acct-Update-Time']).strftime('%s')
                )

                if dt_transfer[port][U] == dt_transfer[port][D] == 0:
                    # No traffic, but not timed out either
                    if seconds_since_last_update < config.RADIUS_IDLE_TIMEOUT:
                        continue
                    # No traffic and timed out
                    attrs = {
                        'status_type': 'Stop',
                        'terminatecause': 'Idle-Timeout',
                    }
                else:
                    attrs = {
                        'status_type': 'Interim-Update',
                    }

                attrs.update({
                    'username': acct['User-Name'],
                    'sessionid': acct['Acct-Session-Id'],
                    'sessiontime': seconds_since_start,
                    'inputoctets': int(acct['Acct-Input-Octets']) + dt_transfer[port][D],
                    'outputoctets': int(acct['Acct-Output-Octets']) + dt_transfer[port][U],
                })
            else:
                attrs.update({
                    'status_type': 'Start',
                    'username': users[port]['User-Name'],
                    'sessionid': 'ss-{node_name}-{port}-{ts}'.format(
                        node_name=config.NODE_NAME, port=port, ts=now.strftime('%s'),
                    ),
                })
            DbTransfer.send_radius_acct(**attrs)

        if config.SS_VERBOSE: logging.info('Accts sent to RADIUS')

    @staticmethod
    def update_servers(users):
        """
        - Stop a server if the user is disabled or runs out of bwlimit
        - Restart a server if the user changes the encryption method
        - Start a valid server if it's not running (normally, newly added servers)
        """
        for port in users:
            user = users[port]
            server = json.loads(DbTransfer.send_command(
                'stat: {"server_port":%s}' % port))
            if server['stat'] != 'ko':
                if user.get('Auth-Type') == 'Reject':
                    # stop suspended or terminated user
                    logging.info(
                        'U[%d] Server has been stopped: user is disabled' % port)
                    DbTransfer.send_command(
                        'remove: {"server_port":%d}' % port)
                elif server['password'] != user['Cleartext-Password']:
                    # password changed
                    logging.info(
                        'U[%d] Server is restarting: password is changed' % port)
                    DbTransfer.send_command(
                        'remove: {"server_port":%d}' % port)
                else:
                    if not config.CUSTOM_METHOD:
                        user['SS-Method'] = config.SS_METHOD
                    if server['method'] != user['SS-Method']:
                        # encryption method changed
                        logging.info(
                            'U[%d] Server is restarting: encryption method is changed' % port)
                        DbTransfer.send_command(
                            'remove: {"server_port":%d}' % port)
            else:
                if not config.CUSTOM_METHOD:
                    user['SS-Method'] = config.SS_METHOD
                DbTransfer.send_command(
                    'add: {"server_port": %d, "password":"%s", "method":"%s"}' % (port, user['Cleartext-Password'], user['SS-Method']))
                if config.MANAGE_BIND_IP != '127.0.0.1':
                    logging.info(
                        'U[%s] Server Started with password [%s] and method [%s]' % (port, user['Cleartext-Password'], user['SS-Method']))

    @staticmethod
    def thread_pull():
        """
        - Pull all users from radcheck
        - Update local subservers according to users fetched in the first step

        dt_transfer NOT required.
        """
        socket.setdefaulttimeout(config.DB_TIMEOUT)
        while True:
            try:
                users = DbTransfer.pull_all_users()
                DbTransfer.update_servers(users)
            except Exception as e:
                if config.SS_VERBOSE:
                    import traceback
                    traceback.print_exc()
                logging.error('Except thrown while pulling user data:%s' % e)
            finally:
                time.sleep(config.CHECKTIME)

    @staticmethod
    def thread_push():
        """
        - Pull all active acct sessions on this SS node
        - Clean up all obsoleted acct sessions
        - Send 'Interim-Update' or 'Stop' acct req accordingly
        """
        socket.setdefaulttimeout(config.DB_TIMEOUT)
        while True:
            try:
                DbTransfer.clean_obsolete_accts()

                users = DbTransfer.pull_all_users()
                accts = DbTransfer.pull_all_accts()
                DbTransfer.push_all_users(users, accts)
            except Exception as e:
                import traceback
                if config.SS_VERBOSE:
                    traceback.print_exc()
                logging.error('Except thrown while pushing user data:%s' % e)
            finally:
                time.sleep(config.SYNCTIME)

    @staticmethod
    def clean_obsolete_accts():
        """
        This method runs on each pull_all_users().

        - Fetch all obsoleted sessions on this SS node.
        - Send "Stop" acct req via radclient to clean up those sessions.

        After fetching all users from radcheck, all obsoleted sessions will be removed.
        """
        conn = DbTransfer.get_db_conn()
        cur = conn.cursor()
        dead_acctupdatetime = datetime.utcnow() - timedelta(seconds=config.RADIUS_IDLE_TIMEOUT * 3)

        cur.execute(
            "SELECT acctsessionid, username, calledstationid, "
            "       acctstarttime, acctinputoctets, acctoutputoctets "
            "FROM   radacct "
            "WHERE  callingstationid = %s AND acctstoptime IS NULL AND acctupdatetime < %s",
            (config.NODE_NAME, transform_datetime(dead_acctupdatetime), )
        )

        for row in cur.fetchall():
            acctsessionid, username, calledstationid, acctstarttime, inputoctets, outputoctets = row
            DbTransfer.send_radius_acct(
                status_type='Stop',
                username=username,
                port=calledstationid,
                sessionid=acctsessionid,
                sessiontime=transform_datetime(datetime.utcnow() - transform_datetime(acctstarttime)),
                inputoctets=inputoctets or 0,
                outputoctets=outputoctets or 0,
                terminatecause='Lost-Carrier',
            )

        cur.close()
        conn.close()
        if config.SS_VERBOSE: logging.info('Obsoleted accts removed')

    @staticmethod
    def pull_all_accts():
        """
        Fetch all active acct sessions on this SS node.
        """
        accts = {}
        conn = DbTransfer.get_db_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT acctsessionid, username, acctstarttime, acctupdatetime, "
            "       acctinputoctets, acctoutputactets, calledstationid, "
            "FROM   radacct "
            "WHERE  callingstationid = %s AND acctstoptime IS NULL",
            (config.NODE_NAME, )
        )

        for acct in cur.fetchall():
            sessionid, username, starttime, updatetime, inputoctets, outputoctets, calledstationid = acct
            accts[calledstationid] = {
                'User-Name': username,
                'Acct-Session-Id': sessionid,
                'Acct-Start-Time': starttime,
                'Acct-Update-Time': updatetime,
                'Acct-Input-Octets': inputoctets,
                'Acct-Output-Octets': outputoctets,
                'Called-Station-Id': calledstationid,
            }

        cur.close()
        conn.close()

        if config.SS_VERBOSE: logging.info('Accts fetched from DB')
        return accts

    @staticmethod
    def pull_all_users():
        conn = DbTransfer.get_db_conn()
        cur = conn.cursor()

        cur.execute("SELECT username, value FROM radcheck WHERE attribute = 'SS-Port'")
        username2port = dict([(row[0], row[1]) for row in cur.fetchall() if row[1] not in config.SS_SKIP_PORTS])
        port2username = dict([(v, k) for k, v in username2port.items()])

        users = {}
        attrs = ('SS-Port', 'SS-Method', 'Auth-Type', 'Cleartext-Password', )

        for attr in attrs:
            cur.execute(
                "SELECT username, value FROM radcheck where attribute = %s AND username in %s",
                (attr, username2port.keys(), )
            )

            for row in cur.fetchall():
                username, value = row
                if value:
                    users[username2port[username]].update({attr: value})

        for port in users:
            users[port].update({'User-Name': port2username[port]})

        cur.close()
        conn.close()

        if config.SS_VERBOSE: logging.info('Users fetched from DB')
        return users
