/*
 * QEMU Management Protocol
 *
 * Copyright IBM, Corp. 2011
 *
 * Authors:
 *  Anthony Liguori   <aliguori@us.ibm.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 * Contributions after 2012-01-13 are licensed under the terms of the
 * GNU GPL, version 2 or (at your option) any later version.
 */

#include "qemu-common.h"
#include "sysemu/sysemu.h"
#include "qmp-commands.h"
#include "sysemu/char.h"
#include "ui/qemu-spice.h"
#include "ui/vnc.h"
#include "sysemu/kvm.h"
#include "sysemu/arch_init.h"
#include "hw/qdev.h"
#include "sysemu/blockdev.h"
#include "qom/qom-qobject.h"
#include "hw/boards.h"
#include "qmp-schema.h"
#include "qapi/qmp/qjson.h"

NameInfo *qmp_query_name(Error **errp)
{
    NameInfo *info = g_malloc0(sizeof(*info));

    if (qemu_name) {
        info->has_name = true;
        info->name = g_strdup(qemu_name);
    }

    return info;
}

VersionInfo *qmp_query_version(Error **err)
{
    VersionInfo *info = g_malloc0(sizeof(*info));
    const char *version = QEMU_VERSION;
    char *tmp;

    info->qemu.major = strtol(version, &tmp, 10);
    tmp++;
    info->qemu.minor = strtol(tmp, &tmp, 10);
    tmp++;
    info->qemu.micro = strtol(tmp, &tmp, 10);
    info->package = g_strdup(QEMU_PKGVERSION);

    return info;
}

KvmInfo *qmp_query_kvm(Error **errp)
{
    KvmInfo *info = g_malloc0(sizeof(*info));

    info->enabled = kvm_enabled();
    info->present = kvm_available();

    return info;
}

UuidInfo *qmp_query_uuid(Error **errp)
{
    UuidInfo *info = g_malloc0(sizeof(*info));
    char uuid[64];

    snprintf(uuid, sizeof(uuid), UUID_FMT, qemu_uuid[0], qemu_uuid[1],
                   qemu_uuid[2], qemu_uuid[3], qemu_uuid[4], qemu_uuid[5],
                   qemu_uuid[6], qemu_uuid[7], qemu_uuid[8], qemu_uuid[9],
                   qemu_uuid[10], qemu_uuid[11], qemu_uuid[12], qemu_uuid[13],
                   qemu_uuid[14], qemu_uuid[15]);

    info->UUID = g_strdup(uuid);
    return info;
}

void qmp_quit(Error **err)
{
    no_shutdown = 0;
    qemu_system_shutdown_request();
}

void qmp_stop(Error **errp)
{
    if (runstate_check(RUN_STATE_INMIGRATE)) {
        autostart = 0;
    } else {
        vm_stop(RUN_STATE_PAUSED);
    }
}

void qmp_system_reset(Error **errp)
{
    qemu_system_reset_request();
}

void qmp_system_powerdown(Error **erp)
{
    qemu_system_powerdown_request();
}

void qmp_cpu(int64_t index, Error **errp)
{
    /* Just do nothing */
}

void qmp_cpu_add(int64_t id, Error **errp)
{
    if (current_machine->hot_add_cpu) {
        current_machine->hot_add_cpu(id, errp);
    } else {
        error_setg(errp, "Not supported");
    }
}

#ifndef CONFIG_VNC
/* If VNC support is enabled, the "true" query-vnc command is
   defined in the VNC subsystem */
VncInfo *qmp_query_vnc(Error **errp)
{
    error_set(errp, QERR_FEATURE_DISABLED, "vnc");
    return NULL;
};
#endif

#ifndef CONFIG_SPICE
/* If SPICE support is enabled, the "true" query-spice command is
   defined in the SPICE subsystem. Also note that we use a small
   trick to maintain query-spice's original behavior, which is not
   to be available in the namespace if SPICE is not compiled in */
SpiceInfo *qmp_query_spice(Error **errp)
{
    error_set(errp, QERR_COMMAND_NOT_FOUND, "query-spice");
    return NULL;
};
#endif

static void iostatus_bdrv_it(void *opaque, BlockDriverState *bs)
{
    bdrv_iostatus_reset(bs);
}

static void encrypted_bdrv_it(void *opaque, BlockDriverState *bs)
{
    Error **err = opaque;

    if (!error_is_set(err) && bdrv_key_required(bs)) {
        error_set(err, QERR_DEVICE_ENCRYPTED, bdrv_get_device_name(bs),
                  bdrv_get_encrypted_filename(bs));
    }
}

void qmp_cont(Error **errp)
{
    Error *local_err = NULL;

    if (runstate_needs_reset()) {
        error_set(errp, QERR_RESET_REQUIRED);
        return;
    } else if (runstate_check(RUN_STATE_SUSPENDED)) {
        return;
    }

    bdrv_iterate(iostatus_bdrv_it, NULL);
    bdrv_iterate(encrypted_bdrv_it, &local_err);
    if (local_err) {
        error_propagate(errp, local_err);
        return;
    }

    if (runstate_check(RUN_STATE_INMIGRATE)) {
        autostart = 1;
    } else {
        vm_start();
    }
}

void qmp_system_wakeup(Error **errp)
{
    qemu_system_wakeup_request(QEMU_WAKEUP_REASON_OTHER);
}

ObjectPropertyInfoList *qmp_qom_list(const char *path, Error **errp)
{
    Object *obj;
    bool ambiguous = false;
    ObjectPropertyInfoList *props = NULL;
    ObjectProperty *prop;

    obj = object_resolve_path(path, &ambiguous);
    if (obj == NULL) {
        error_set(errp, QERR_DEVICE_NOT_FOUND, path);
        return NULL;
    }

    QTAILQ_FOREACH(prop, &obj->properties, node) {
        ObjectPropertyInfoList *entry = g_malloc0(sizeof(*entry));

        entry->value = g_malloc0(sizeof(ObjectPropertyInfo));
        entry->next = props;
        props = entry;

        entry->value->name = g_strdup(prop->name);
        entry->value->type = g_strdup(prop->type);
    }

    return props;
}

/* FIXME: teach qapi about how to pass through Visitors */
int qmp_qom_set(Monitor *mon, const QDict *qdict, QObject **ret)
{
    const char *path = qdict_get_str(qdict, "path");
    const char *property = qdict_get_str(qdict, "property");
    QObject *value = qdict_get(qdict, "value");
    Error *local_err = NULL;
    Object *obj;

    obj = object_resolve_path(path, NULL);
    if (!obj) {
        error_set(&local_err, QERR_DEVICE_NOT_FOUND, path);
        goto out;
    }

    object_property_set_qobject(obj, value, property, &local_err);

out:
    if (local_err) {
        qerror_report_err(local_err);
        error_free(local_err);
        return -1;
    }

    return 0;
}

int qmp_qom_get(Monitor *mon, const QDict *qdict, QObject **ret)
{
    const char *path = qdict_get_str(qdict, "path");
    const char *property = qdict_get_str(qdict, "property");
    Error *local_err = NULL;
    Object *obj;

    obj = object_resolve_path(path, NULL);
    if (!obj) {
        error_set(&local_err, QERR_DEVICE_NOT_FOUND, path);
        goto out;
    }

    *ret = object_property_get_qobject(obj, property, &local_err);

out:
    if (local_err) {
        qerror_report_err(local_err);
        error_free(local_err);
        return -1;
    }

    return 0;
}

void qmp_set_password(const char *protocol, const char *password,
                      bool has_connected, const char *connected, Error **errp)
{
    int disconnect_if_connected = 0;
    int fail_if_connected = 0;
    int rc;

    if (has_connected) {
        if (strcmp(connected, "fail") == 0) {
            fail_if_connected = 1;
        } else if (strcmp(connected, "disconnect") == 0) {
            disconnect_if_connected = 1;
        } else if (strcmp(connected, "keep") == 0) {
            /* nothing */
        } else {
            error_set(errp, QERR_INVALID_PARAMETER, "connected");
            return;
        }
    }

    if (strcmp(protocol, "spice") == 0) {
        if (!using_spice) {
            /* correct one? spice isn't a device ,,, */
            error_set(errp, QERR_DEVICE_NOT_ACTIVE, "spice");
            return;
        }
        rc = qemu_spice_set_passwd(password, fail_if_connected,
                                   disconnect_if_connected);
        if (rc != 0) {
            error_set(errp, QERR_SET_PASSWD_FAILED);
        }
        return;
    }

    if (strcmp(protocol, "vnc") == 0) {
        if (fail_if_connected || disconnect_if_connected) {
            /* vnc supports "connected=keep" only */
            error_set(errp, QERR_INVALID_PARAMETER, "connected");
            return;
        }
        /* Note that setting an empty password will not disable login through
         * this interface. */
        rc = vnc_display_password(NULL, password);
        if (rc < 0) {
            error_set(errp, QERR_SET_PASSWD_FAILED);
        }
        return;
    }

    error_set(errp, QERR_INVALID_PARAMETER, "protocol");
}

void qmp_expire_password(const char *protocol, const char *whenstr,
                         Error **errp)
{
    time_t when;
    int rc;

    if (strcmp(whenstr, "now") == 0) {
        when = 0;
    } else if (strcmp(whenstr, "never") == 0) {
        when = TIME_MAX;
    } else if (whenstr[0] == '+') {
        when = time(NULL) + strtoull(whenstr+1, NULL, 10);
    } else {
        when = strtoull(whenstr, NULL, 10);
    }

    if (strcmp(protocol, "spice") == 0) {
        if (!using_spice) {
            /* correct one? spice isn't a device ,,, */
            error_set(errp, QERR_DEVICE_NOT_ACTIVE, "spice");
            return;
        }
        rc = qemu_spice_set_pw_expire(when);
        if (rc != 0) {
            error_set(errp, QERR_SET_PASSWD_FAILED);
        }
        return;
    }

    if (strcmp(protocol, "vnc") == 0) {
        rc = vnc_display_pw_expire(NULL, when);
        if (rc != 0) {
            error_set(errp, QERR_SET_PASSWD_FAILED);
        }
        return;
    }

    error_set(errp, QERR_INVALID_PARAMETER, "protocol");
}

#ifdef CONFIG_VNC
void qmp_change_vnc_password(const char *password, Error **errp)
{
    if (vnc_display_password(NULL, password) < 0) {
        error_set(errp, QERR_SET_PASSWD_FAILED);
    }
}

static void qmp_change_vnc_listen(const char *target, Error **errp)
{
    vnc_display_open(NULL, target, errp);
}

static void qmp_change_vnc(const char *target, bool has_arg, const char *arg,
                           Error **errp)
{
    if (strcmp(target, "passwd") == 0 || strcmp(target, "password") == 0) {
        if (!has_arg) {
            error_set(errp, QERR_MISSING_PARAMETER, "password");
        } else {
            qmp_change_vnc_password(arg, errp);
        }
    } else {
        qmp_change_vnc_listen(target, errp);
    }
}
#else
void qmp_change_vnc_password(const char *password, Error **errp)
{
    error_set(errp, QERR_FEATURE_DISABLED, "vnc");
}
static void qmp_change_vnc(const char *target, bool has_arg, const char *arg,
                           Error **errp)
{
    error_set(errp, QERR_FEATURE_DISABLED, "vnc");
}
#endif /* !CONFIG_VNC */

void qmp_change(const char *device, const char *target,
                bool has_arg, const char *arg, Error **err)
{
    if (strcmp(device, "vnc") == 0) {
        qmp_change_vnc(target, has_arg, arg, err);
    } else {
        qmp_change_blockdev(device, target, arg, err);
    }
}

static void qom_list_types_tramp(ObjectClass *klass, void *data)
{
    ObjectTypeInfoList *e, **pret = data;
    ObjectTypeInfo *info;

    info = g_malloc0(sizeof(*info));
    info->name = g_strdup(object_class_get_name(klass));

    e = g_malloc0(sizeof(*e));
    e->value = info;
    e->next = *pret;
    *pret = e;
}

ObjectTypeInfoList *qmp_qom_list_types(bool has_implements,
                                       const char *implements,
                                       bool has_abstract,
                                       bool abstract,
                                       Error **errp)
{
    ObjectTypeInfoList *ret = NULL;

    object_class_foreach(qom_list_types_tramp, implements, abstract, &ret);

    return ret;
}

DevicePropertyInfoList *qmp_device_list_properties(const char *typename,
                                                   Error **errp)
{
    ObjectClass *klass;
    Property *prop;
    DevicePropertyInfoList *prop_list = NULL;

    klass = object_class_by_name(typename);
    if (klass == NULL) {
        error_set(errp, QERR_DEVICE_NOT_FOUND, typename);
        return NULL;
    }

    klass = object_class_dynamic_cast(klass, TYPE_DEVICE);
    if (klass == NULL) {
        error_set(errp, QERR_INVALID_PARAMETER_VALUE,
                  "name", TYPE_DEVICE);
        return NULL;
    }

    do {
        for (prop = DEVICE_CLASS(klass)->props; prop && prop->name; prop++) {
            DevicePropertyInfoList *entry;
            DevicePropertyInfo *info;

            /*
             * TODO Properties without a parser are just for dirty hacks.
             * qdev_prop_ptr is the only such PropertyInfo.  It's marked
             * for removal.  This conditional should be removed along with
             * it.
             */
            if (!prop->info->set) {
                continue;           /* no way to set it, don't show */
            }

            info = g_malloc0(sizeof(*info));
            info->name = g_strdup(prop->name);
            info->type = g_strdup(prop->info->legacy_name ?: prop->info->name);

            entry = g_malloc0(sizeof(*entry));
            entry->value = info;
            entry->next = prop_list;
            prop_list = entry;
        }
        klass = object_class_get_parent(klass);
    } while (klass != object_class_by_name(TYPE_DEVICE));

    return prop_list;
}

CpuDefinitionInfoList *qmp_query_cpu_definitions(Error **errp)
{
    return arch_query_cpu_definitions(errp);
}

/*
 * Use a string to record the visit path, type index of each node
 * will be saved to the string, indexes are split by ':'.
 */
static char visit_path_str[1024];

/* push the type index to visit_path_str */
static void push_id(int id)
{
    char *end = strrchr(visit_path_str, ':');
    char type_idx[256];
    int num;

    num = sprintf(type_idx, "%d:", id);

    if (end) {
        /* avoid overflow */
        assert(end - visit_path_str + 1 + num < sizeof(visit_path_str));
        sprintf(end + 1, "%d:", id);
    } else {
        sprintf(visit_path_str, "%d:", id);
    }
}

/* pop the type index from visit_path_str */
static void pop_id(void)
{
    char *p = strrchr(visit_path_str, ':');

    assert(p != NULL);
    *p = '\0';
    p = strrchr(visit_path_str, ':');
    if (p) {
        *(p + 1) = '\0';
    } else {
        visit_path_str[0] = '\0';
    }
}

static const char *qstring_copy_str(QObject *data)
{
    QString *qstr;

    if (!data) {
        return NULL;
    }
    qstr = qobject_to_qstring(data);
    if (qstr) {
        return qstring_get_str(qstr);
    } else {
        return NULL;
    }
}

static DataObject *visit_qobj_dict(QObject *data);
static DataObject *visit_qobj_list(QObject *data);

static QObject *get_definition(const char *str, bool update_path)
{
    QObject *data, *value;
    QDict *qdict;
    int i;

    if (!strcmp(str, "str") || !strcmp(str, "int") ||
        !strcmp(str, "number") || !strcmp(str, "bool") ||
        !strcmp(str, "int8") || !strcmp(str, "int16") ||
        !strcmp(str, "int32") || !strcmp(str, "int64") ||
        !strcmp(str, "uint8") || !strcmp(str, "uint16") ||
        !strcmp(str, "uint32") || !strcmp(str, "uint64") ||
        !strcmp(str, "visitor") || !strcmp(str, "**") ||
        !strcmp(str, "size")) {
        /* native type */
        return NULL;
    }

    for (i = 0; qmp_schema_table[i]; i++) {
        data = qobject_from_json(qmp_schema_table[i]);
        qdict = qobject_to_qdict(data);
        assert(qdict != NULL);

        if (qdict_get(qdict, "enum")) {
            value = qdict_get(qdict, "enum");
        } else if (qdict_get(qdict, "type")) {
            value = qdict_get(qdict, "type");
        } else if (qdict_get(qdict, "union")) {
            value = qdict_get(qdict, "union");
        } else {
            continue;
        }

        if (!strcmp(str, qstring_copy_str(value))) {

            if (update_path) {
                char *start, *end;
                char cur_idx[256];
                char type_idx[256];

                start = visit_path_str;
                sprintf(type_idx, "%d", i);
                while(start) {
                    end = strchr(start, ':');
                    if (!end) {
                        break;
                    }
                    snprintf(cur_idx, end - start + 1, "%s", start);
                    start = end + 1;
                    /* if the type was already extended in parent node,
                     * we don't extend it again to avoid dead loop. */
                    if (!strcmp(cur_idx, type_idx)) {
                        return NULL;
                    }
                }
                /* push index to visit_path_str before extending */
                push_id(i);
            }

            return qobject_from_json(qmp_schema_table[i]);
        }
    }
    return NULL;
}

/* extend defined type to json object */
static DataObject *extend_type(const char *str)
{
    QObject *data;
    DataObject *obj;

    data = get_definition(str, true);

    if (data) {
        obj = visit_qobj_dict(data);
        pop_id();
    } else {
        obj = g_malloc0(sizeof(struct DataObject));
        obj->kind = DATA_OBJECT_KIND_REFERENCE_TYPE;
        obj->reference_type = g_malloc0(sizeof(String));
        obj->reference_type->str = g_strdup(str);
    }

    return obj;
}

static DataObjectMemberList *list_to_memberlist(QObject *data)
{
    DataObjectMemberList *mem_list, *entry, *last_entry;
    QList *qlist;
    const QListEntry *lent;

        qlist = qobject_to_qlist(data);

        mem_list = NULL;
        for (lent = qlist_first(qlist); lent; lent = qlist_next(lent)) {
            entry = g_malloc0(sizeof(DataObjectMemberList *));
            entry->value = g_malloc0(sizeof(DataObjectMember));
            entry->value->type = g_malloc0(sizeof(DataObjectMemberType));

            if (get_definition(qstring_copy_str(lent->value), false)) {
                entry->value->type->kind = DATA_OBJECT_MEMBER_TYPE_KIND_EXTEND;
                entry->value->has_recursive = true;
                entry->value->recursive = true;
                entry->value->type->extend =
                    extend_type(qstring_copy_str(lent->value));

	    } else {
                entry->value->type->kind = DATA_OBJECT_MEMBER_TYPE_KIND_REFERENCE;
                entry->value->has_recursive = true;
                entry->value->recursive = false;
                entry->value->type->reference =
                    g_strdup(qstring_copy_str(lent->value));
	    }

            entry->next = NULL;
            if (!mem_list) {
                mem_list = entry;
            } else {
                last_entry->next = entry;
            }
            last_entry = entry;
        }
        return mem_list;
}

static DataObjectMemberList *dict_to_memberlist(QObject *data)
{
    DataObjectMemberList *mem_list, *entry, *last_entry;
    QDict *qdict;
    const QDictEntry *dent;

        qdict = qobject_to_qdict(data);

        mem_list = NULL;
        for (dent = qdict_first(qdict); dent; dent = qdict_next(qdict, dent)) {
            entry = g_malloc0(sizeof(DataObjectMemberList *));
            entry->value = g_malloc0(sizeof(DataObjectMember));

            entry->value->type = g_malloc0(sizeof(DataObjectMemberType));

            if (dent->value->type->code == QTYPE_QDICT) {
		entry->value->type->kind = DATA_OBJECT_MEMBER_TYPE_KIND_EXTEND;
		entry->value->type->extend = visit_qobj_dict(dent->value);
            } else if (dent->value->type->code == QTYPE_QLIST) {
		entry->value->type->kind = DATA_OBJECT_MEMBER_TYPE_KIND_EXTEND;
		entry->value->type->extend = visit_qobj_list(dent->value);
            } else if (get_definition(qstring_copy_str(dent->value), false)) {
                entry->value->type->kind = DATA_OBJECT_MEMBER_TYPE_KIND_EXTEND;
                entry->value->has_recursive = true;
                entry->value->recursive = true;
                entry->value->type->extend =
                    extend_type(qstring_copy_str(dent->value));
	    } else {
                entry->value->type->kind = DATA_OBJECT_MEMBER_TYPE_KIND_REFERENCE;
                entry->value->has_recursive = true;
                entry->value->recursive = false;
                entry->value->type->reference = g_strdup(qstring_copy_str(dent->value));
	    }
            entry->value->has_optional = true;
            entry->value->has_name = true;
	    if (dent->key[0] == '*') {
                entry->value->optional = true;
                entry->value->name = g_strdup(dent->key + 1);
	    } else {
                entry->value->name = g_strdup(dent->key);
            }

            entry->next = NULL;
            if (!mem_list) {
                mem_list = entry;
            } else {
                last_entry->next = entry;
            }
            last_entry = entry;
        }
        return mem_list;
}

static DataObject *visit_qobj_list(QObject *data)
{
    DataObject *obj;

    obj = g_malloc0(sizeof(struct DataObject));
    obj->kind = DATA_OBJECT_KIND_UNDEFINED_STRUCT;
    obj->undefined_struct = g_malloc0(sizeof(struct
                                             DataObjectUndefinedStruct));
    obj->undefined_struct->data = list_to_memberlist(data);

    return obj;
}

static strList *get_str_list(QObject *data)
{
    strList *str_list, *last_str_entry, *str_entry;
    QList *qlist;
    const QListEntry *lent;

    qlist = qobject_to_qlist(data);
    str_list = NULL;
    for (lent = qlist_first(qlist); lent; lent = qlist_next(lent)) {
        str_entry = g_malloc0(sizeof(strList *));
        str_entry->value = g_strdup(qstring_copy_str(lent->value));
        str_entry->next = NULL;
        if (!str_list) {
            str_list = str_entry;
        } else {
            last_str_entry->next = str_entry;
        }
        last_str_entry = str_entry;
    }

    return str_list;
}
static DataObject *visit_qobj_dict(QObject *data)
{
    DataObject *obj;
    QObject *subdata;
    QDict *qdict;

    qdict = qobject_to_qdict(data);
    assert(qdict != NULL);
    obj = g_malloc0(sizeof(*obj));

    if (qdict_get(qdict, "command")) {
        obj->kind = DATA_OBJECT_KIND_COMMAND;
        obj->has_name = true;
        obj->name = g_strdup(qstring_copy_str(qdict_get(qdict, "command")));
        obj->command = g_malloc0(sizeof(struct DataObjectCommand));

        subdata = qdict_get(qdict, "data");
        if (subdata && subdata->type->code == QTYPE_QDICT) {
            obj->command->has_data = true;
            obj->command->data = dict_to_memberlist(subdata);
        } else if (subdata && subdata->type->code == QTYPE_QLIST) {
             abort();
        } else if (subdata) {
            obj->command->has_data = true;
            obj->command->data =
                dict_to_memberlist(get_definition(qstring_copy_str(subdata),
                                                  true));
            pop_id();
        }

        subdata = qdict_get(qdict, "returns");
        if (subdata && subdata->type->code == QTYPE_QDICT) {
            abort();
        } else if (subdata && subdata->type->code == QTYPE_QLIST) {
            obj->command->has_returns = true;
	    obj->command->returns = visit_qobj_list(subdata);
        } else if (subdata && subdata->type->code == QTYPE_QSTRING) {
            obj->command->has_returns = true;
            obj->command->returns = extend_type(qstring_copy_str(subdata));
        }

        subdata = qdict_get(qdict, "gen");
        if (subdata && subdata->type->code == QTYPE_QSTRING) {
            obj->command->has_gen = true;
            if (!strcmp(qstring_copy_str(subdata), "no")) {
                obj->command->gen = false;
            } else {
                obj->command->gen = true;
            }
        }
    } else if (qdict_get(qdict, "union")) {
        obj->kind = DATA_OBJECT_KIND_UNIONOBJ;
        obj->has_name = true;
        obj->name = g_strdup(qstring_copy_str(qdict_get(qdict, "union")));
        obj->unionobj = g_malloc0(sizeof(struct DataObjectUnion));
        subdata = qdict_get(qdict, "data");
        obj->unionobj->data = dict_to_memberlist(subdata);
    } else if (qdict_get(qdict, "type")) {
        obj->kind = DATA_OBJECT_KIND_TYPE;
        obj->has_name = true;
        obj->name = g_strdup(qstring_copy_str(qdict_get(qdict, "type")));
        obj->type = g_malloc0(sizeof(struct DataObjectType));
        subdata = qdict_get(qdict, "data");
        obj->type->data = dict_to_memberlist(subdata);
    } else if (qdict_get(qdict, "enum")) {
        obj->kind = DATA_OBJECT_KIND_ENUMERATION;
        obj->has_name = true;
        obj->name = g_strdup(qstring_copy_str(qdict_get(qdict, "enum")));
        obj->enumeration = g_malloc0(sizeof(struct DataObjectEnumeration));
        subdata = qdict_get(qdict, "data");
        obj->enumeration->data = get_str_list(subdata);
    } else {
        obj->kind = DATA_OBJECT_KIND_UNDEFINED_STRUCT;
        obj->undefined_struct = g_malloc0(sizeof(struct
                                                 DataObjectUndefinedStruct));
        obj->undefined_struct->data = dict_to_memberlist(data);
    }

    return obj;
}

DataObjectList *qmp_query_qmp_schema(Error **errp)
{
    DataObjectList *list, *last_entry, *entry;
    QObject *data;
    int i;

    list = NULL;
    for (i = 0; qmp_schema_table[i]; i++) {
        data = qobject_from_json(qmp_schema_table[i]);
        assert(data != NULL);

        entry = g_malloc0(sizeof(DataObjectList *));
        memset(visit_path_str, 0, sizeof(visit_path_str));
        entry->value = visit_qobj_dict(data);
        entry->next = NULL;
        if (!list) {
            list = entry;
        } else {
            last_entry->next = entry;
        }
        last_entry = entry;
    }

    return list;
}

void qmp_add_client(const char *protocol, const char *fdname,
                    bool has_skipauth, bool skipauth, bool has_tls, bool tls,
                    Error **errp)
{
    CharDriverState *s;
    int fd;

    fd = monitor_get_fd(cur_mon, fdname, errp);
    if (fd < 0) {
        return;
    }

    if (strcmp(protocol, "spice") == 0) {
        if (!using_spice) {
            error_set(errp, QERR_DEVICE_NOT_ACTIVE, "spice");
            close(fd);
            return;
        }
        skipauth = has_skipauth ? skipauth : false;
        tls = has_tls ? tls : false;
        if (qemu_spice_display_add_client(fd, skipauth, tls) < 0) {
            error_setg(errp, "spice failed to add client");
            close(fd);
        }
        return;
#ifdef CONFIG_VNC
    } else if (strcmp(protocol, "vnc") == 0) {
        skipauth = has_skipauth ? skipauth : false;
        vnc_display_add_client(NULL, fd, skipauth);
        return;
#endif
    } else if ((s = qemu_chr_find(protocol)) != NULL) {
        if (qemu_chr_add_client(s, fd) < 0) {
            error_setg(errp, "failed to add client");
            close(fd);
            return;
        }
        return;
    }

    error_setg(errp, "protocol '%s' is invalid", protocol);
    close(fd);
}
