/* mmcsv2json.c
 * Parse all fields of the message into structured data inside the
 * JSON tree.
 *
 * Copyright 2013 Adiscon GmbH.
 *
 * This file is part of rsyslog.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *       http://www.apache.org/licenses/LICENSE-2.0
 *       -or-
 *       see COPYING.ASL20 in the source distribution
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "config.h"
#include "rsyslog.h"
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <stdint.h>
#include "conf.h"
#include "syslogd-types.h"
#include "srUtils.h"
#include "template.h"
#include "module-template.h"
#include "errmsg.h"
#include <csv.h>
#include <ctype.h>
#include <stdlib.h>

MODULE_TYPE_OUTPUT
MODULE_TYPE_NOKEEP
MODULE_CNFNAME("mmcsv2json")


DEFobjCurrIf(errmsg)
DEF_OMOD_STATIC_DATA

/* config variables */

/* define operation modes we have */
#define SIMPLE_MODE 0     /* just overwrite */
#define REWRITE_MODE 1     /* rewrite IP address, canoninized */

typedef struct fields_s {
    size_t count; 
    uchar **data;
} fields_t;
typedef struct _instanceData {
    uchar separator;
    uchar quote;
    uchar detect_number;
    fields_t fields;
    uchar *jsonRoot;    /**< container where to store fields */
} instanceData;

typedef struct wrkrInstanceData {
    instanceData *pData;
} wrkrInstanceData_t;

struct modConfData_s {
    rsconf_t *pConf;    /* our overall config object */
};
static modConfData_t *loadModConf = NULL;/* modConf ptr to use for the current load process */
static modConfData_t *runModConf = NULL;/* modConf ptr to use for the current exec process */


/* tables for interfacing with the v6 config system */
/* action (instance) parameters */
static struct cnfparamdescr actpdescr[] = {
    { "separator", eCmdHdlrGetChar, 0 },
    { "quote", eCmdHdlrGetChar, 0 },
    { "jsonroot", eCmdHdlrString, 0 },
    { "detect_number", eCmdHdlrString, 0},
    { "fields", eCmdHdlrArray, 0}
};
static struct cnfparamblk actpblk =
    { CNFPARAMBLK_VERSION,
      sizeof(actpdescr)/sizeof(struct cnfparamdescr),
      actpdescr
    };

BEGINbeginCnfLoad
CODESTARTbeginCnfLoad
    loadModConf = pModConf;
    pModConf->pConf = pConf;
ENDbeginCnfLoad

BEGINendCnfLoad
CODESTARTendCnfLoad
ENDendCnfLoad

BEGINcheckCnf
CODESTARTcheckCnf
ENDcheckCnf

BEGINactivateCnf
CODESTARTactivateCnf
    runModConf = pModConf;
ENDactivateCnf

BEGINfreeCnf
CODESTARTfreeCnf
ENDfreeCnf


BEGINcreateInstance
CODESTARTcreateInstance
ENDcreateInstance

BEGINcreateWrkrInstance
CODESTARTcreateWrkrInstance
ENDcreateWrkrInstance


BEGINisCompatibleWithFeature
CODESTARTisCompatibleWithFeature
ENDisCompatibleWithFeature


BEGINfreeInstance
CODESTARTfreeInstance
    size_t j;
    free(pData->jsonRoot);
    if(pData->fields.count > 0) {
        for(j = 0 ; j < pData->fields.count; ++j) {
            free(pData->fields.data[j]);
            pData->fields.data[j] = NULL;
        }
    }
    if(pData->fields.data != NULL) {
        free(pData->fields.data);
    }
ENDfreeInstance

BEGINfreeWrkrInstance
CODESTARTfreeWrkrInstance
ENDfreeWrkrInstance


static inline void
setInstParamDefaults(instanceData *pData)
{
    pData->quote = '"';
    pData->separator = ',';
    pData->jsonRoot = NULL;
    pData->fields.count = 0;
    pData->fields.data = NULL;
}

BEGINnewActInst
    struct cnfparamvals *pvals;
    size_t i, j;
CODESTARTnewActInst
    DBGPRINTF("newActInst (mmcsv2json)\n");
    if((pvals = nvlstGetParams(lst, &actpblk, NULL)) == NULL) {
        ABORT_FINALIZE(RS_RET_MISSING_CNFPARAMS);
    }

    CODE_STD_STRING_REQUESTnewActInst(1)
    CHKiRet(OMSRsetEntry(*ppOMSR, 0, NULL, OMSR_TPL_AS_MSG));
    CHKiRet(createInstance(&pData));
    setInstParamDefaults(pData);

    for(i = 0 ; i < actpblk.nParams ; ++i) {
        if(!pvals[i].bUsed)
            continue;
        if(!strcmp(actpblk.descr[i].name, "separator")) {
            pData->separator = es_getBufAddr(pvals[i].val.d.estr)[0];
        } else if(!strcmp(actpblk.descr[i].name, "quote")) {
            pData->quote = es_getBufAddr(pvals[i].val.d.estr)[0];
        } else if(!strcmp(actpblk.descr[i].name, "jsonroot")) {
            pData->jsonRoot = (uchar*)es_str2cstr(pvals[i].val.d.estr, NULL);
        } else if(!strcmp(actpblk.descr[i].name, "detect_number")) {
            pData->detect_number = es_getBufAddr(pvals[i].val.d.estr)[0] == '1';
        } else if(!strcmp(actpblk.descr[i].name, "fields")) {
            pData->fields.count = pvals[i].val.d.ar->nmemb;
            if( pData->fields.count > 0) {
                CHKmalloc(pData->fields.data = malloc(sizeof(uchar*) * pData->fields.count));
                
                for(j = 0 ; j <  pData->fields.count; ++j) {
                    pData->fields.data[j] = (uchar*)es_str2cstr(pvals[i].val.d.ar->arr[j], NULL);
                }
            }
        } else {
            dbgprintf("mmcsv2json: program error, non-handled "
              "param '%s'\n", actpblk.descr[i].name);
        }
    }
    if(pData->jsonRoot == NULL) {
        CHKmalloc(pData->jsonRoot = (uchar*) strdup("!"));
    }

CODE_STD_FINALIZERnewActInst
    cnfparamvalsDestruct(pvals, &actpblk);
ENDnewActInst


BEGINdbgPrintInstInfo
CODESTARTdbgPrintInstInfo
ENDdbgPrintInstInfo


BEGINtryResume
CODESTARTtryResume
ENDtryResume

struct mmcsv2json_ctx {
    instanceData * conf;
    msg_t * msg;
    struct json_object * json;
    size_t fieldindex;
};

static int number_detect(char * s, size_t len, double * n) {
    char * endptr = NULL;
    errno = 0;
    *n = strtod(s, &endptr);
    return errno == 0 && *endptr == '\0' && s != endptr ? 1 : 0;
}

void field_cb (void *s, size_t len, void *data) {
    //((struct counts *)data)->fields++;
    double d;
    uchar buf[256] = {0};
    uchar fieldname[512] = {0}, *fn;
    json_object * jval;
    struct mmcsv2json_ctx * ctx = (struct mmcsv2json_ctx *) data;
    memcpy(buf, s, len > sizeof(buf) ? sizeof(buf) - 1 : len);

    if(ctx->fieldindex < ctx->conf->fields.count) {
        fn = ctx->conf->fields.data[ctx->fieldindex]; 
    } else {
        snprintf((char*) fieldname, sizeof(fieldname), "f%ld", ctx->fieldindex);
        fn = fieldname;
    }
    DBGPRINTF("mmcsv2json: field %ld: '%s' = '%s'\n", ctx->fieldindex, fn, (char*) buf);

    if(ctx->conf->detect_number && number_detect(s, len, &d)) {
        jval = json_object_new_double(d);
    } else {
        jval = json_object_new_string_len((char*) s, len);
    }
    json_object_object_add(ctx->json, (char*) fn, jval);

    DBGPRINTF("mmcsv2json: current field count: %d\n", json_object_get_member_count(ctx->json));

    ctx->fieldindex ++;
}

void record_cb (int c, void *data) {
    struct mmcsv2json_ctx * ctx = (struct mmcsv2json_ctx *) data;

    DBGPRINTF("mmcsv2json: field count: %d\n", json_object_get_member_count(ctx->json));

    msgAddJSON(ctx->msg, ctx->conf->jsonRoot, ctx->json, 0, 0);
}

static rsRetVal
parse_fields(instanceData *pData, msg_t *pMsg, uchar *msgtext, size_t lenMsg)
{
    struct csv_parser p;
    struct mmcsv2json_ctx ctx;

    struct json_object *json;
    int field;
    DEFiRet;

    json =  json_object_new_object();
    if(json == NULL) {
        ABORT_FINALIZE(RS_RET_ERR);
    }
    field = 1;

    if(csv_init(&p, CSV_APPEND_NULL) != 0) {
        json_object_put(json);
        ABORT_FINALIZE(RS_RET_ERR);  
    }
    ctx.json = json;
    ctx.fieldindex = 0;
    ctx.conf = pData;
    ctx.msg = pMsg;

    csv_set_delim(&p, pData->separator);
    csv_set_quote(&p, pData->quote);

    if( csv_parse(&p, msgtext, lenMsg, field_cb, record_cb, &ctx) != lenMsg) {
        errmsg.LogError(0, RS_RET_INVALID_VALUE,
            "mmcsv2json: error while parsing file: %s\n", 
            csv_strerror(csv_error(&p)));
        goto finalize_it;
    }

    csv_fini(&p, field_cb, record_cb, &ctx);

    csv_free(&p);

    ctx.json = NULL;
    ctx.msg = NULL;
    ctx.conf = NULL;
    ctx.fieldindex = 0;

finalize_it:
    RETiRet;
}


BEGINdoAction_NoStrings
    msg_t **ppMsg = (msg_t **) pMsgData;
    msg_t *pMsg = ppMsg[0];
    uchar *msg;
    size_t lenMsg;
CODESTARTdoAction
    lenMsg = getMSGLen(pMsg);
    msg = getMSG(pMsg);
    CHKiRet(parse_fields(pWrkrData->pData, pMsg, msg, lenMsg));
finalize_it:
ENDdoAction


BEGINparseSelectorAct
CODESTARTparseSelectorAct
CODE_STD_STRING_REQUESTparseSelectorAct(1)
    if(strncmp((char*) p, ":mmcsv2json:", sizeof(":mmcsv2json:") - 1)) {
        errmsg.LogError(0, RS_RET_LEGA_ACT_NOT_SUPPORTED,
            "mmcsv2json supports only v6+ config format, use: "
            "action(type=\"mmcsv2json\" ...)");
    }
    ABORT_FINALIZE(RS_RET_CONFLINE_UNPROCESSED);
CODE_STD_FINALIZERparseSelectorAct
ENDparseSelectorAct


BEGINmodExit
CODESTARTmodExit
    objRelease(errmsg, CORE_COMPONENT);
ENDmodExit


BEGINqueryEtryPt
CODESTARTqueryEtryPt
CODEqueryEtryPt_STD_OMOD_QUERIES
CODEqueryEtryPt_STD_OMOD8_QUERIES
CODEqueryEtryPt_STD_CONF2_OMOD_QUERIES
CODEqueryEtryPt_STD_CONF2_QUERIES
ENDqueryEtryPt



BEGINmodInit()
CODESTARTmodInit
    *ipIFVersProvided = CURR_MOD_IF_VERSION; /* we only support the current interface specification */
CODEmodInit_QueryRegCFSLineHdlr
    DBGPRINTF("mmcsv2json: module compiled with rsyslog version %s.\n", VERSION);
    CHKiRet(objUse(errmsg, CORE_COMPONENT));
ENDmodInit
