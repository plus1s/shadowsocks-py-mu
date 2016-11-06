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

import os
import json
import time
import pytz
import config
import socket
import logging
import psycopg2

from collections import defaultdict
from datetime import datetime, timedelta

from pyrad import client as pyradclient
from pyrad.dictionary import Dictionary
from shadowsocks.common import U, D


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
            reply = radclient.SendPacket(req)
            logging.info("RADIUS: reply code {}".format(reply.code))
        except pyradclient.Timeout:
            logging.warn('RADIUS: server does not reply')
        except socket.error as error:
            logging.warn('RADIUS: network error: {}'.format(error[1]))

    @staticmethod
    def send_radius_acct(attrs):
        if isinstance(attrs, dict):
            attrs = [attrs]

        radclient = DbTransfer.get_radclient()

        for attr in attrs:
            req = radclient.CreateAcctPacket(User_Name=attr['username'])
            req['Acct-Status-Type'] = attr['status_type']
            req['Acct-Session-Id'] = attr['sessionid']
            req['Called-Station-Id'] = attr['port']
            req['Calling-Station-Id'] = config.NODE_NAME
            req['NAS-Port-Id'] = 'ShadowSocks'
            req['NAS-IP-Address'] = config.RADIUS_NAS_IP

            if attr['status_type'] in ('Interim-Update', 'Stop'):
                req['Acct-Session-Time'] = attr.get('sessiontime', 0)
                req['Acct-Input-Octets'] = attr.get('inputoctets', 0)
                req['Acct-Output-Octets'] = attr.get('outputoctets', 0)
                if attr['status_type'] == 'Stop':
                    req['Acct-Terminate-Cause'] = attr.get('terminatecause', 'Idle-Timeout')

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
        return pyradclient.Client(server=config.RADIUS_SERVER, secret=config.RADIUS_SECRET,
                                  dict=Dictionary(config.RADIUS_DICTIONARY))

    @staticmethod
    def get_users_from_cache():
        with open(config.USERS_CACHE, 'r') as f:
            users = json.load(f)
        return users

    @staticmethod
    def thread_runner(function, interval):
        socket.setdefaulttimeout(config.DB_TIMEOUT)
        while True:
            try:
                getattr(DbTransfer, function)()
            except Exception as e:
                if config.SS_VERBOSE:
                    import traceback
                    traceback.print_exc()
                logging.error('Except thrown while running {}: {}'.format(function, e))
            finally:
                time.sleep(interval)

    @staticmethod
    def push_all_accts(accts):
        users = DbTransfer.get_users_from_cache()
        dt_transfer = DbTransfer.get_servers_transfer()
        now = pytz.utc.localize(datetime.utcnow())

        all_ports = list(set(dt_transfer.keys()).union(set(accts.keys())))
        attrs = []

        for port in all_ports:
            attr = {'port': port}

            if port in accts:
                # Ports in accts are the ones have active acct sessions open.
                acct = accts[port]
                seconds_since_start = int((now - acct['Acct-Start-Time']).total_seconds())
                seconds_since_last_update = int((now - acct['Acct-Update-Time']).total_seconds())

                attr.update({
                    'username': acct['User-Name'],
                    'sessionid': acct['Acct-Session-Id'],
                    'sessiontime': seconds_since_start,
                })

                if port in dt_transfer:
                    # So this port shows up in both accts and dt_transfer.
                    # Just send interim updates to it to update the traffic usage.

                    attr.update({
                        'status_type': 'Interim-Update',
                        'inputoctets': acct['Acct-Input-Octets'] + dt_transfer[port][D],
                        'outputoctets': acct['Acct-Output-Octets'] + dt_transfer[port][U],
                    })

                else:
                    # This port does have active acct sessions, but has no traffic since last update.
                    if seconds_since_last_update < config.RADIUS_IDLE_TIMEOUT:
                        # Skip to process the next port, because the session hasn't timed out yet.
                        if config.SS_VERBOSE: logging.info('P[{}] U[{}]: no traffic, skipping'
                                                           .format(port, acct['User-Name'], ))
                        continue
                    else:
                        # Send `Stop` to close the timed out session.
                        if config.SS_VERBOSE: logging.info('P[{}] U[{}]: no traffic, sending Idle-Timeout'
                                                           .format(port, acct['User-Name'], ))
                        attr.update({
                            'status_type': 'Stop',
                            'inputoctets': acct['Acct-Input-Octets'],
                            'outputoctets': acct['Acct-Output-Octets'],
                            'terminatecause': 'Idle-Timeout',
                        })
                attrs.append(attr.copy())
            else:
                attr.update({
                    'status_type': 'Start',
                    'username': users[port]['User-Name'],
                    'sessionid': 'ss-{node_name}-{port}-{ts}'.format(
                        node_name=config.NODE_NAME, port=port, ts=now.strftime('%s'),
                    ),
                })
                attrs.append(attr.copy())
                attr.update({
                    'status_type': 'Interim-Update',
                    'inputoctets': dt_transfer[port][D],
                    'outputoctets': dt_transfer[port][U],
                })
                attrs.append(attr.copy())

        if attrs: DbTransfer.send_radius_acct(attrs)
        if config.SS_VERBOSE: logging.info('{} accts sent to RADIUS'.format(len(attrs)))

    @staticmethod
    def update_accts():
        DbTransfer.clean_obsolete_accts()
        accts = DbTransfer.pull_all_accts()
        DbTransfer.push_all_accts(accts)

    @staticmethod
    def update_servers():
        """
        - Stop a server if the user is disabled or runs out of bwlimit
        - Restart a server if the user changes the encryption method
        - Start a valid server if it's not running (normally, newly added servers)
        """
        users = DbTransfer.pull_all_users()
        for port in users:
            user = users[port]
            server = json.loads(DbTransfer.send_command(
                'stat: {"server_port":%s}' % port))
            if server['stat'] != 'ko':
                if user.get('Auth-Type') == 'Reject':
                    # stop suspended or terminated user
                    logging.info(
                        'U[%s] Server has been stopped: user is disabled' % port)
                    DbTransfer.send_command(
                        'remove: {"server_port":%s}' % port)
                elif server['password'] != user['Cleartext-Password']:
                    # password changed
                    logging.info(
                        'U[%s] Server is restarting: password is changed' % port)
                    DbTransfer.send_command(
                        'remove: {"server_port":%s}' % port)
                else:
                    if not config.CUSTOM_METHOD:
                        user['SS-Method'] = config.SS_METHOD
                    if server['method'] != user['SS-Method']:
                        # encryption method changed
                        logging.info(
                            'P[%s] Server is restarting: encryption method is changed' % port)
                        DbTransfer.send_command(
                            'remove: {"server_port":%s}' % port)
            else:
                if not config.CUSTOM_METHOD:
                    user['SS-Method'] = config.SS_METHOD
                DbTransfer.send_command(
                    'add: {"server_port": %s, "password":"%s", "method":"%s", "username":"%s"}' % (port, user['Cleartext-Password'], user['SS-Method'], user['User-Name']))
                if config.MANAGE_BIND_IP != '127.0.0.1':
                    logging.info(
                        'P[%s] Server Started with username [%s] password [%s] and method [%s]' % (port, user['User-Name'], user['Cleartext-Password'], user['SS-Method']))

    @staticmethod
    def clean_obsolete_accts():
        """
        - Fetch all obsoleted sessions on this SS node.
        - Send "Stop" acct req via radclient to clean up those sessions.

        After fetching all users from radcheck, all obsoleted sessions will be removed.
        """
        conn = DbTransfer.get_db_conn()
        cur = conn.cursor()
        now = pytz.utc.localize(datetime.utcnow())
        dead_acctupdatetime = now - timedelta(seconds=config.RADIUS_IDLE_TIMEOUT * 3)

        cur.execute(
            "SELECT acctsessionid, username, calledstationid, "
            "       acctstarttime, acctinputoctets, acctoutputoctets "
            "FROM   radacct "
            "WHERE  callingstationid = %s AND acctstoptime IS NULL AND acctupdatetime < %s",
            (config.NODE_NAME, dead_acctupdatetime, )
        )

        attrs = []

        for row in cur.fetchall():
            acctsessionid, username, calledstationid, acctstarttime, inputoctets, outputoctets = row
            attr = {
                'status_type': 'Stop',
                'username': username,
                'port': calledstationid,
                'sessionid': acctsessionid,
                'sessiontime': int((now - acctstarttime).total_seconds()),
                'inputoctets': inputoctets or 0,
                'outputoctets': outputoctets or 0,
                'terminatecause': 'Lost-Carrier',
            }
            attrs.append(attr)

        cur.close()
        conn.close()

        if attrs: DbTransfer.send_radius_acct(attrs)
        if config.SS_VERBOSE: logging.info('{} obsoleted accts removed'.format(len(attrs)))

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
            "       acctinputoctets, acctoutputoctets, calledstationid "
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

        if config.SS_VERBOSE: logging.info('{} accts pulled from DB'.format(len(accts)))
        return accts

    @staticmethod
    def pull_all_users():
        """
        Fetch all the users has SS-Port set and cache them onto the disk.
        """
        conn = DbTransfer.get_db_conn()
        cur = conn.cursor()

        cur.execute("SELECT username, value FROM radcheck WHERE attribute = 'SS-Port'")
        username2port = dict([(row[0], row[1]) for row in cur.fetchall() if row[1] not in config.SS_SKIP_PORTS])
        port2username = dict([(v, k) for k, v in username2port.items()])

        users = defaultdict(dict)
        attrs = ('SS-Method', 'Auth-Type', 'Cleartext-Password', )

        for attr in attrs:
            cur.execute(
                "SELECT username, value FROM radcheck WHERE attribute = %s AND username IN %s",
                (attr, tuple(username2port.keys()), )
            )

            for row in cur.fetchall():
                username, value = row
                if value:
                    users[username2port[username]].update({attr: value})

        for port in port2username:
            users[port].update({
                'SS-Port': port,
                'User-Name': port2username[port],
            })

        cur.close()
        conn.close()

        # Dump users onto disk
        with open(config.USERS_CACHE_TMP, 'w') as f:
            json.dump(users, f)
        os.rename(config.USERS_CACHE_TMP, config.USERS_CACHE)

        if config.SS_VERBOSE: logging.info('{} users pulled from DB and dumped'.format(len(users)))

        return users
