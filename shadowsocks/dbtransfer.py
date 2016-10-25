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

import sys
import json
import time
import socket
import logging
import pyrad
import config

if config.DB_TYPE == 'mysql':
    import cymysql
elif config.DB_TYPE == 'postgresql':
    import psycopg2
else:
    logging.critical('CRIT: Please set DB_TYPE in your config file.')
    sys.exit(2)

from shadowsocks.common import U, D


class DbTransfer(object):

    instance = None

    def __init__(self):
        self.last_get_transfer = {}

    @staticmethod
    def get_instance():
        if DbTransfer.instance is None:
            DbTransfer.instance = DbTransfer()
        return DbTransfer.instance

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
        if config.DB_TYPE == 'mysql':
            conn = cymysql.connect(host=config.DB_HOST, port=config.DB_PORT, user=config.DB_USER,
                                   passwd=config.DB_PASS, db=config.DB_NAME, charset='utf8')
        else:  # postgresql
            conn = psycopg2.connect(host=config.DB_HOST, port=config.DB_PORT, user=config.DB_USER,
                                    password=config.DB_PASS, database=config.DB_NAME)
        return conn

    def push_db_all_user(self):
        dt_transfer = self.get_servers_transfer()
        query_head = 'UPDATE %s' % config.DB_USER_TABLE
        query_sub_when = ''
        query_sub_when2 = ''
        query_sub_in = None
        last_time = time.time()
        for port in dt_transfer.keys():
            query_sub_when += ' WHEN %s THEN u + %s' % (
                port, dt_transfer[port][U])
            query_sub_when2 += ' WHEN %s THEN d + %s' % (
                port, dt_transfer[port][D])
            if query_sub_in is not None:
                query_sub_in += ',%s' % port
            else:
                query_sub_in = '%s' % port
        if query_sub_when == '':
            return
        query_sql = query_head + ' SET u = CASE port' + query_sub_when + \
            ' END, d = CASE port' + query_sub_when2 + \
            ' END, t = ' + str(int(last_time)) + \
            ' WHERE port IN (%s)' % query_sub_in
        # print query_sql
        conn = DbTransfer.get_db_conn()
        cur = conn.cursor()
        cur.execute(query_sql)
        cur.close()
        conn.commit()
        conn.close()
        if config.SS_VERBOSE:
            logging.info('db uploaded')

    @staticmethod
    def update_servers(rows):
        """
        - Stop a server if the user is disabled or runs out of bwlimit
        - Restart a server if the user changes the encryption method
        - Start a valid server if it's not running (normally, newly added servers)
        """
        for row in rows:
            server = json.loads(DbTransfer.get_instance().send_command(
                'stat: {"server_port":%s}' % row[0]))
            if server['stat'] != 'ko':
                if row[5] == 0 or row[6] == 0:
                    # stop disabled or switched-off user
                    logging.info(
                        'U[%d] Server has been stopped: user is disabled' % row[0])
                    DbTransfer.send_command(
                        'remove: {"server_port":%d}' % row[0])
                elif row[1] + row[2] >= row[3]:
                    # stop user that exceeds bandwidth limit
                    logging.info(
                        'U[%d] Server has been stopped: bandwith exceeded' % row[0])
                    DbTransfer.send_command(
                        'remove: {"server_port":%d}' % row[0])
                elif server['password'] != row[4]:
                    # password changed
                    logging.info(
                        'U[%d] Server is restarting: password is changed' % row[0])
                    DbTransfer.send_command(
                        'remove: {"server_port":%d}' % row[0])
                else:
                    if not config.CUSTOM_METHOD:
                        row[7] = config.SS_METHOD
                    if server['method'] != row[7]:
                        # encryption method changed
                        logging.info(
                            'U[%d] Server is restarting: encryption method is changed' % row[0])
                        DbTransfer.send_command(
                            'remove: {"server_port":%d}' % row[0])
            else:
                if row[5] == 1 and row[6] == 1 and row[1] + row[2] < row[3]:
                    if not config.CUSTOM_METHOD:
                        row[7] = config.SS_METHOD
                    DbTransfer.send_command(
                        'add: {"server_port": %d, "password":"%s", "method":"%s", "email":"%s"}' % (row[0], row[4], row[7], row[8]))
                    if config.MANAGE_BIND_IP != '127.0.0.1':
                        logging.info(
                            'U[%s] Server Started with password [%s] and method [%s]' % (row[0], row[4], row[7]))

    @staticmethod
    def thread_db():
        socket.setdefaulttimeout(config.DB_TIMEOUT)
        while True:
            try:
                rows = DbTransfer.pull_db_all_user()
                DbTransfer.update_servers(rows)
            except Exception as e:
                if config.SS_VERBOSE:
                    import traceback
                    traceback.print_exc()
                logging.error('Except thrown while pulling user data:%s' % e)
            finally:
                time.sleep(config.CHECKTIME)

    @staticmethod
    def thread_push():
        socket.setdefaulttimeout(config.DB_TIMEOUT)
        while True:
            try:
                DbTransfer.get_instance().push_db_all_user()
            except Exception as e:
                import traceback
                if config.SS_VERBOSE:
                    traceback.print_exc()
                logging.error('Except thrown while pushing user data:%s' % e)
            finally:
                time.sleep(config.SYNCTIME)

    @staticmethod
    def pull_db_all_user():
        strings = ['']
        for port in config.SS_SKIP_PORTS:
            if config.SS_VERBOSE:
                logging.info('db skipped port %d' % port)
            if not config.SS_SKIP_PORTS.index(port):
                strings.append('WHERE')
            else:
                strings.append('AND')
            strings.append('port <> {}'.format(port))
        conn = DbTransfer.get_db_conn()
        cur = conn.cursor()
        cur.execute('SELECT port, u, d, transfer_enable, passwd, switch, enable, method, email FROM %s%s ORDER BY port ASC'
                    % (config.DB_USER_TABLE, ' '.join(strings)))
        rows = map(list, cur.fetchall())
        # Release resources
        cur.close()
        conn.close()
        if config.SS_VERBOSE:
            logging.info('db downloaded')
        return rows
