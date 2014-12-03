#!/usr/bin/env python

import os
import sys
import re
import requests
import syslog
import hashlib
import gzip

from operator import itemgetter
from datetime import datetime
from sqlalchemy import create_engine
from sqlalchemy import exc
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy.pool import NullPool

# Convert from Heroku style DATABASE_URL to Sqlalchemy style, if necessary 
db_url = os.environ.get('DATABASE_URL')
DATABASE_URL = re.sub('^postgres:', 'postgresql:', db_url)
OFFSET_FILE_NAME = '.last-log-offset'

engine = create_engine(DATABASE_URL, poolclass=NullPool)
Base = declarative_base(engine)

class User(Base):
    """"""
    __tablename__ = 'auth_user'
    __table_args__ = {'autoload':True}

class Instance(Base):
    """"""
    __tablename__ = 'launcher_instance'
    __table_args__ = {'autoload':True}
 
class MCSession(Base):
    """"""
    __tablename__ = 'launcher_session'
    __table_args__ = {'autoload':True}

# Add foreign key relationships    
MCSession.user = relationship(User, primaryjoin=MCSession.user_id == User.id)
MCSession.instance = relationship(Instance, primaryjoin=MCSession.instance_id == Instance.id)
 
def loadSession():
    """"""
    metadata = Base.metadata
    Session = sessionmaker(bind=engine)
    session = Session()
    return session

def get_instance_id():
    """Use EC2 metadata to get instance id."""
    response = requests.get('http://169.254.169.254/latest/meta-data/instance-id')
    return response.text

def login(session, player_name, login_time):
    user = session.query(User).\
                filter(User.username == player_name).\
                one()
    instance = session.query(Instance).\
                    filter(Instance.name == get_instance_id()).\
                    one()
    login_dt = datetime.strptime(login_time,'%Y-%m-%d %H:%M:%S')
    mc_session = MCSession(user_id=user.id,
                           instance_id=instance.id,
                           login=login_dt)
    session.add(mc_session)
    try:
        session.commit()
    except exc.IntegrityError:
        session.rollback()
    except:
        raise
    # Remove obj from session, so subsequent logouts in same DB session will
    # work. (Foreign key relations will be part of obj upon requerying DB.)
    if mc_session in session:
        session.expunge(mc_session)


def logout(session, player_name, logout_time):
    instance_name = get_instance_id()
    logout_dt = datetime.strptime(logout_time,'%Y-%m-%d %H:%M:%S')
    session.query(MCSession).\
        join(User).\
        join(Instance).\
        filter(MCSession.logout==None).\
        filter(User.username==player_name).\
        filter(Instance.name==instance_name).\
        update({'logout': logout_dt})
    session.commit()

def get_matching_sha1(fileobj, num_bytes, target_sha1):
    '''
    checks to see if a partial log file matches the sha1 hash
    of the last read file

    returns a hashlib object of the matching sha1 hash. None if no match
    '''

    try:
        fileobj.seek(0)
        trunc_file_data = fileobj.read(num_bytes)

        if len(trunc_file_data) == num_bytes:
            sha1 = hashlib.sha1()
            sha1.update(trunc_file_data)
            if sha1.hexdigest() == target_sha1:
                return sha1
    except IOError as ioe:
        syslog.syslog(syslog.LOG_WARNING, 'Cant read logfile %s: %s' %
                                          (fileobj.name, ioe.message))
    return None

def _parse_log_dir(logdir):
    '''
    parses the passed in log directory for log file names.
    returns a list of tuples of 3 items: (datetime, num, filename)
    
    datetime object corresponds to the date of the log file. Note
    that 'lastest.log' will have datetime set to datettime.today()
    and num of maxint

    num corresponds to the -# that follows the log's YYYY-MM-DD.

    the filename is the actual filename of the log (basename only)
    '''

    logname_re = re.compile(r'^(?P<date>\d{4}-\d{2}-\d{2}|latest)'
                            r'-?(?P<num>\d+|\b).log(.gz|\b)$')
    for log_name in os.listdir(logdir):
        match = logname_re.match(log_name)
        if match:
            date = match.group('date')
            num = match.group('num')
            if date == 'latest':
                date = datetime.today()
                num = sys.maxint
            else:
                date = datetime.strptime(date, '%Y-%m-%d')
                num = int(num)
            yield (date, num, log_name)

def get_sorted_log_list(logdir):
    '''
    sorts the list from _parse_log_dir by the datetime and num
    of the log file in order of most recent date -> earliest.

    returns a list of logfile paths and the log date in string format
    '''
    return [(os.path.join(logdir, p[2]), p[0].strftime('%Y-%m-%d'))
            for p in sorted(_parse_log_dir(logdir),
                            key=itemgetter(0,1),
                            reverse=True)]

def iterate_log_and_save(logdate, logfile, offset=0, sha1=None):
    '''
    iterates through the lines in a logfile (starting from whereever
    the filepointer is) and will subsequently save the length off
    the file and it's sha1 hash into a hidden file for later reference.

    This should be used as a generator

    optionally, the starting offset and sha1 hashlib object can be
    passed in case we are not starting at the beginning of the file
    '''
    if not sha1:
        sha1 = hashlib.sha1()
    for line in logfile:
        offset += len(line)
        sha1.update(line)
        yield '[%s]%s' % (logdate, line)

    record_last_offset(logfile, offset, sha1)

def record_last_offset(logfile, offset, sha1):
    '''
    records the length and sha1 hash of a file in the same directory
    as the file with a hidden file
    '''

    logdir = os.path.dirname(logfile.name)
    offset_file_path = os.path.join(logdir, OFFSET_FILE_NAME)
    with open(offset_file_path, 'wb') as offset_file:
        offset_file = open(offset_file_path, 'wb')
        offset_file.write('%d\n%s\n' % (offset, sha1.hexdigest()))

def get_last_offset(logdir):
    '''
    attempts to retrieve the last length and sha1 hash of the log file
    read by this script.

    returns a tuple (offset, sha1 hexdigest)
    
    If the file is not present, or unreadable, a -1 will be returned
    for the offset
    '''
    offset_file_path = os.path.join(logdir, OFFSET_FILE_NAME)
    offdata = (-1, None)
    if not os.path.isfile(offset_file_path):
        return offdata

    of_lines = ['-1', '']
    try:
        with open(offset_file_path, 'rb') as of:
            of = open(offset_file_path, 'rb')
            of_lines = of.readlines()
    except IOError as ioe:
        syslog.syslog(syslog.LOG_WARNING,
                     'Could not open the last offset file %s : %s' %
                     (offset_file_path, ioe.message))

    return (int(of_lines[0].strip('\n'), 10), of_lines[1].strip('\n'))


def iterate_unread_lines(logdir):
    '''
    given a logdir, this functions as a generator to
    read through all unread lines in a directory.

    this function will save the offset and sha1 hash of
    the last read file.
    '''

    offset, last_sha1_digest = get_last_offset(logdir)
    latest_path = os.path.join(logdir, 'latest.log')
    todaysdate = datetime.today().strftime('%Y-%m-%d')

    #no existing data, just iterate through the latest.log
    if offset < 0:
        with open(latest_path, 'rb') as latest:
            for line in iterate_log_and_save(todaysdate, latest):
                yield line
    else:
        log_list = get_sorted_log_list(logdir)
        log_process_sequence = [log_list[0]]
        sha1_obj = None
        for i, log_data in enumerate(log_list):
            logpath, logdate = log_data
            open_op = gzip.open if 'log.gz' in logpath\
                                else open
            with open_op(logpath, 'rb') as logfile:
                sha1_obj = get_matching_sha1(logfile, offset, last_sha1_digest)
                if sha1_obj:
                    log_process_sequence = log_list[:i]
                    log_process_sequence.reverse()
                    for line in iterate_log_and_save(logdate, logfile, offset, sha1_obj):
                        yield line
                    break

        if log_process_sequence:
            last_log_id = len(log_process_sequence) - 1
            for i, log_data in enumerate(log_process_sequence):
                logpath, logdate = log_data
                open_op = gzip.open if 'log.gz' in logpath\
                                    else open
                with open_op(logpath, 'rb') as logfile:
                    if i == last_log_id:
                        for line in iterate_log_and_save(logdate, logfile):
                            yield line
                    else:
                        for line in logfile:
                            yield '[%s]%s' % (logdate, line)
def main():
    session = loadSession()

    # FIXME: Don't hardcode server name. Handle multiple worlds?
    LOG_DIR = '/opt/msm/servers/default/logs'
    # Regexes
    date_pat = r'\[(\d{4}-\d{2}-\d{2})\]' # normally, there is no date (just time). But this script will append
                                      # a date to each line for time keeping purposes while parsing
    time_pat = r'\[(\d{2}:\d{2}:\d{2})\]'
    timestamp = date_pat + time_pat
    pri = r'\[Server thread/INFO\]:'
    fmt_str = '%s %s %s'
    login_regex = re.compile(fmt_str % (timestamp, pri, r'(.+)\[/([0-9.]+):\d+\] logged in'))
    logout_regex = re.compile(fmt_str % (timestamp, pri, r'(.+) left the game'))

    for line in iterate_unread_lines(LOG_DIR):
        login_match = login_regex.search(line)
        logout_match = logout_regex.search(line)
        if login_match:
            (date, time, player_name, ip) = login_match.groups()
            login(session, player_name, '%s %s' % (date, time))
        elif logout_match:
            (date, time, player_name) = logout_match.groups()
            logout(session, player_name, '%s %s' % (date, time))


if __name__ == "__main__":
    main()
