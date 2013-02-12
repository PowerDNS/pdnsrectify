#!/usr/bin/env python
from sqlalchemy import ForeignKey, Column, Table, Sequence
from sqlalchemy.types import TypeDecorator, Integer, Boolean, Unicode, UnicodeText, DateTime, LargeBinary
from sqlalchemy.ext.declarative import declarative_base, DeferredReflection

from sqlalchemy import orm, create_engine, select, func, desc, or_

from sqlalchemy.orm import relationship

import sys, hashlib, base64, string
from collections import defaultdict

Base = declarative_base(cls=DeferredReflection)

class Domain(Base):
    __tablename__ = 'domains'
    records = relationship("Record")

class Record(Base):
    __tablename__ = 'records'
    domain_id = Column(Integer, ForeignKey('domains.id'))

    def __repr__(self):
        return '%s/%s/%s' % (self.id, self.name, self.type)

class DomainMetaData(Base):
    __tablename__ = 'domainmetadata'
    domain_id = Column(Integer, ForeignKey('domains.id'))

def chopoff(s):
    if '.' in s:
        return s[s.find('.')+1:]
    else:
        return ''

def childof(qname, dels):
    while True:
        if qname in dels:
            return True
        qname = chopoff(qname)
        if not qname:
            return False

def sha1(s):
    d = hashlib.sha1()
    d.update(s)
    return d.digest()

def wirename(s):
    return ''.join(chr(len(label))+label for label in s.split('.'))+chr(0)

def hash(qname, params):
    # code kindly copied from http://pypi.python.org/pypi/django-powerdns-manager
    algo, flags, iterations, salt = params.split()
    
    qname = wirename(qname.encode('ascii'))
    
    # Prepare salt
    salt = salt.decode('hex')
    
    hashed_name = sha1(qname+salt)
    i = 0
    while i < int(iterations):
        hashed_name = sha1(hashed_name+salt)
        i += 1
    
    # Do standard base32 encoding
    final_data = base64.b32encode(hashed_name)
    # Apply the translation table to convert to base32hex encoding.
    final_data = final_data.translate(
        string.maketrans('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567',
        '0123456789ABCDEFGHIJKLMNOPQRSTUV'))

    # Return lower case representation as required by PowerDNS
    return final_data.lower()

def reverse(qname, domain):
    if qname != domain and not qname.endswith('.'+domain):
        raise Exception('%s not in %s during reverse()' % (qname, domain))
    if qname == domain:
        return ''
    qname = qname[:-len(domain)-1]
    return ' '.join(reversed(qname.split('.')))    

def main():
    def getmeta(domid):
        metadata = db_session.query(DomainMetaData).filter_by(domain_id=domid).all()
        d = dict()
        for m in metadata:
            d[m.kind] = m.content
        return d

    dbfile = sys.argv[1]
    domain = sys.argv[2]

    engine = create_engine('sqlite:///%s' % dbfile, convert_unicode=True)
    sessionmaker = orm.sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db_session = orm.scoped_session(sessionmaker)
    Base.prepare(engine)

    domainobj = db_session.query(Domain).filter_by(name=domain).one()
    domid = domainobj.id
    meta = getmeta(domid)
    nsec3param = meta.get('NSEC3PARAM')
    narrow = nsec3param and 'NSEC3NARROW' in meta

    records = defaultdict(list)

    qnames = set()
    delegations = set()
    nonempty = set()
    empty = set()
    emptyneeded = set()
    authnames = set()

    for record in db_session.query(Record).filter_by(domain_id=domid):
        records[record.name].append(record)
        qnames.add(record.name)
        if(record.type):
            nonempty.add(record.name)
            qnames.add(record.name)
            if(record.type == 'NS' and record.name != domain):
                delegations.add(record.name)
        else:
            empty.add(record.name)
        if(record.auth):
            authnames.add(record.name)

    intersect = empty.intersection(nonempty)
    if intersect:
        print 'empty/nonempty intersection: %s' % (sorted(list(intersect)))

    if nsec3param and not narrow:
        hashed = dict((qname, hash(qname, nsec3param)) for qname in qnames)

    for name, recs in records.iteritems():
        indelegation = childof(name, delegations)
        isdelegation = name in delegations

        if name != domain:
            if chopoff(name) not in qnames and not childof(name, delegations):
                print 'next closer for %s missing' % name 

        for rec in recs:
            # print indelegation, rec.name, rec.auth
            if indelegation:
                if isdelegation:
                    if rec.type == 'NS':
                        if rec.auth:
                            print rec, 'is auth delegation'
                    elif rec.type == 'DS':
                        if not rec.auth:
                            print rec, 'is unauth secure delegation'
                    else: # type not NS/DS
                        if rec.auth:
                            print rec, 'is auth at delegation point'
                else: # not delegation but in delegation
                    if rec.auth:
                        print rec, 'is auth inside delegation occlusion'
            else: # not in delegation
                if not rec.auth:
                    print rec, 'is not auth'


            if nsec3param:
                if narrow:
                    if rec.ordername is not None:
                        print rec, 'has non-NULL ordername in narrow'
                else: # not narrow
                    if rec.auth:
                        if rec.ordername is None:
                            print rec, 'has NULL ordername while auth'
                        elif rec.ordername != hashed[rec.name]:
                            print rec, 'has wrong ordername (should be %s)' % (hashed[rec.name])
            else: # not nsec3
                if (rec.auth or rec.type == 'NS') and rec.type is not None and rec.ordername is None:
                    print rec, 'has NULL ordername'
                if rec.ordername is not None:
                    if rec.ordername != reverse(rec.name, domain):
                        print rec, 'has wrong ordername'

    for name in authnames:
        if name == domain:
            continue
        name = chopoff(name)
        while name and name != domain and name not in nonempty:
            emptyneeded.add(name)
            name = chopoff(name)

    missing = emptyneeded - empty
    superfl = empty - emptyneeded
    if missing:
        print 'missing ENTs: %s' % (sorted(list(missing)))

    if superfl:
        print 'superfluous ENTs: %s' % (sorted(list(superfl)))

if __name__ == '__main__':
    main()