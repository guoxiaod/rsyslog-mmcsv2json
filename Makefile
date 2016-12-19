NAME=rsyslog-mmcsv2json
VERSION=0.1.0
SRCPATH=${NAME}-${VERSION}
SRCFILE=${SRCPATH}.tgz


RSYSLOG_NAME=rsyslog
RSYSLOG_VERSION=8.23.0
RSYSLOG_FILE=${RSYSLOG_NAME}-${RSYSLOG_VERSION}.tar.gz
RSYSLOG_URL=http://www.rsyslog.com/files/download/rsyslog/${RSYSLOG_FILE}

all: fetch build copy

fetch:
	if [ ! -e ${RSYSLOG_FILE} ]; then wget ${RSYSLOG_URL}; fi
	rm -rf ${SRCPATH}
	cp -r src ${SRCPATH}
	rm -rf ${SRCPATH}/${RSYSLOG_NAME}-${RSYSLOG_VERSION}
	rm -rf ${SRCPATH}/${RSYSLOG_NAME}
	cd ${SRCPATH} && tar -xzf ../${RSYSLOG_FILE} && mv ${RSYSLOG_NAME}-${RSYSLOG_VERSION} ${RSYSLOG_NAME}
	tar -czf ${SRCFILE} ${SRCPATH}


build:
	rpmbuild -ta ${SRCFILE}


copy:
	cp ${HOME}/rpmbuild/RPMS/x86_64/${NAME}-*${VERSION}*.rpm .

clean:
	rm -rf *.rpm *.tgz
