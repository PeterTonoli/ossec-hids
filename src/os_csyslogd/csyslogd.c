/* @(#) $Id: ./src/os_csyslogd/csyslogd.c, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * License details at the LICENSE file included with OSSEC or
 * online at: http://www.ossec.net/en/licensing.html
 */



#include "shared.h"

#include "csyslogd.h"
char __shost[512];

#include "os_net/os_net.h"

#include <zmq.h>
#include "cJSON.h"

/* OS_SyslogD: Monitor the alerts and sends them via syslog.
 * Only return in case of error.
 */
void OS_CSyslogD(SyslogConfig **syslog_config)
{
    int s = 0;
    time_t tm;
    struct tm *p;
    //int tries = 0;

    alert_data *al_data;

    /* XXX DEBUG *///
    char address[28];
    strncpy(address, "tcp://127.0.0.1:9010", 21);


    /* Getting currently time before starting */
    tm = time(NULL);
    p = localtime(&tm);


    /* connect to zmq pubsub */
    void *zctx = zmq_ctx_new();
    void *zsub = zmq_socket(zctx, ZMQ_SUB);
    if(zsub == NULL) {
	merror("Cannot setup zmq socket(%d): %s", errno, strerror(errno));
	exit(errno);
    }
    if(zmq_connect(zsub, address) < 0) {
	merror("Cannot connect to: %s (%d): %s", address, errno, strerror(errno));
	exit(errno);
    }
    if(zmq_setsockopt(zsub, ZMQ_SUBSCRIBE, "", 0) < 0) {
	merror("Cannot setsockopt (%d): %s", errno, strerror(errno));
	exit(errno);
    }

    /* Connecting to syslog. */
    s = 0;
    while(syslog_config[s])
    {
        syslog_config[s]->socket = OS_ConnectUDP(syslog_config[s]->port,
                                                 syslog_config[s]->server, 0);
        if(syslog_config[s]->socket < 0)
        {
            merror(CONNS_ERROR, ARGV0, syslog_config[s]->server);
        }
        else
        {
            merror("%s: INFO: Forwarding alerts via syslog to: '%s:%d'.",
                   ARGV0, syslog_config[s]->server, syslog_config[s]->port);
        }

        s++;
    }



    /* Infinite loop reading the alerts and inserting them. */
    while(1)
    {
        tm = time(NULL);
        p = localtime(&tm);

	if(!p) { }

	al_data = malloc(sizeof(alert_data));

	memset(al_data, 0, sizeof(alert_data));
	al_data->date = asctime(p);

	/* This isn't available in the json */
	al_data->alertid = 0;

        /* Get message if available */
	cJSON *root, *jrule, *jfile;
	char buf[OS_MAXSTR + 1];
	int zret = zmq_recv(zsub, buf, OS_MAXSTR, 0);
	if(zret < 0) {
		merror("zmq_recv failed (%d): %s", errno, strerror(errno));
		exit(errno);
	} else if(zret > OS_MAXSTR) {
		merror("zmq_recv received more than %d", OS_MAXSTR);
	}
	buf[zret + 1] = '\0';

	if((strncmp("ossec.alerts", buf, 12)) == 0) {
		printf("ossec.alerts: %s\n", buf);
	} else {

		root=cJSON_Parse(buf);
		if(!root) {
			merror("cJSON_Parse failed! Error before: %s\n", cJSON_GetErrorPtr());
			exit(1);
		}

		/* Start filling in the fields */
		if(cJSON_GetObjectItem(root, "location")) {
			al_data->location = cJSON_GetObjectItem(root, "location")->valuestring;
		}
		if(cJSON_GetObjectItem(root, "full_log")) {
			al_data->log[0] = cJSON_GetObjectItem(root, "full_log")->valuestring;
		}

		if(cJSON_GetObjectItem(root, "rule")) {
			jrule = cJSON_GetObjectItem(root, "rule");

			if(cJSON_GetObjectItem(jrule, "level")) {
				al_data->rule = cJSON_GetObjectItem(jrule, "level")->valueint;
			}

			if(cJSON_GetObjectItem(jrule, "comment")) {
				al_data->comment = cJSON_GetObjectItem(jrule, "comment")->valuestring;
			}

			if(cJSON_GetObjectItem(jrule, "sidid")) {
				al_data->rule = cJSON_GetObjectItem(jrule, "sidid")->valueint;
			}


		}

		if(cJSON_GetObjectItem(root, "file")) {
			jfile = cJSON_GetObjectItem(root, "file");

			if(cJSON_GetObjectItem(jfile, "md5_before")) {
				al_data->old_md5 = cJSON_GetObjectItem(jfile, "md5_before")->valuestring;
			}
			if(cJSON_GetObjectItem(jfile, "md5_after")) {
				al_data->new_md5 = cJSON_GetObjectItem(jfile, "md5_after")->valuestring;
			}
			if(cJSON_GetObjectItem(jfile, "sha1_before")) {
				al_data->old_sha1 = cJSON_GetObjectItem(jfile, "sha1_before")->valuestring;
			}
			if(cJSON_GetObjectItem(jfile, "sha1_after")) {
				al_data->new_sha1 = cJSON_GetObjectItem(jfile, "sha1_after")->valuestring;
			}

		}

	}		



        /* Sending via syslog */
        s = 0;
        while(syslog_config[s])
        {
            OS_Alert_SendSyslog(al_data, syslog_config[s]);
            s++;
        }


        /* Clearing the memory */
        FreeAlertData(al_data);
    }
}

/* Format Field for output */
int field_add_string(char *dest, size_t size, const char *format, const char *value ) {
    char buffer[OS_SIZE_2048];
    int len = 0;
    int dest_sz = size - strlen(dest);

    if(dest_sz <= 0 ) {
        // Not enough room in the buffer
        return -1;
    }

    if(value != NULL &&
            (
                ((value[0] != '(') && (value[1] != 'n') && (value[2] != 'o')) ||
                ((value[0] != '(') && (value[1] != 'u') && (value[2] != 'n')) ||
                ((value[0] != 'u') && (value[1] != 'n') && (value[4] != 'k'))
            )
    ) {
        len = snprintf(buffer, sizeof(buffer) - dest_sz - 1, format, value);
        strncat(dest, buffer, dest_sz);
    }

    return len;
}

/* Add a field, but truncate if too long */
int field_add_truncated(char *dest, size_t size, const char *format, const char *value, int fmt_size ) {
    char buffer[OS_SIZE_2048];

    int available_sz = size - strlen(dest);
    int total_sz = strlen(value) + strlen(format) - fmt_size;
    int field_sz = available_sz - strlen(format) + fmt_size;

    int len = 0;
    char trailer[] = "...";
    char *truncated = NULL;

    if(available_sz <= 0 ) {
        // Not enough room in the buffer
        return -1;
    }

    if(value != NULL &&
            (
                ((value[0] != '(') && (value[1] != 'n') && (value[2] != 'o')) ||
                ((value[0] != '(') && (value[1] != 'u') && (value[2] != 'n')) ||
                ((value[0] != 'u') && (value[1] != 'n') && (value[4] != 'k'))
            )
    ) {

        if( (truncated=malloc(field_sz + 1)) != NULL ) {
            if( total_sz > available_sz ) {
                // Truncate and add a trailer
                os_substr(truncated, value, 0, field_sz - strlen(trailer));
                strcat(truncated, trailer);
            }
            else {
                strncpy(truncated,value,field_sz);
            }

            len = snprintf(buffer, available_sz, format, truncated);
            strncat(dest, buffer, available_sz);
        }
        else {
            // Memory Error
            len = -3;
        }
    }
    // Free the temporary pointer
    free(truncated);

    return len;
}

/* Handle integers in the second position */
int field_add_int(char *dest, size_t size, const char *format, const int value ) {
    char buffer[255];
    int len = 0;
    int dest_sz = size - strlen(dest);

    if(dest_sz <= 0 ) {
        // Not enough room in the buffer
        return -1;
    }

    if( value > 0 ) {
        len = snprintf(buffer, sizeof(buffer), format, value);
        strncat(dest, buffer, dest_sz);
    }

    return len;
}
/* EOF */
