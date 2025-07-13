import argparse
import asyncio
from collections import defaultdict
import logging
from msldap.commons.factory import LDAPConnectionFactory
from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR
from winacl.dtyp.security_descriptor import SECURITY_DESCRIPTOR
from impacket.ldap.ldaptypes import LDAP_SID
from uuid import UUID
import json
import cmd
import re
from msada_guids import *
from msldap.ldap_objects import MSADGroup, MSADGMSAUser, MSADMachine, MSADContainer, MSADUser, MSADDMSAUser
from colorama import init, Fore, Style
init()
has_colorama = True
COLOR_HEADER = Fore.YELLOW + Style.BRIGHT
COLOR_DN = Fore.CYAN
COLOR_SID = Fore.MAGENTA
COLOR_ACE = Fore.GREEN
COLOR_VALUE = Fore.WHITE + Style.BRIGHT
COLOR_RESET = Style.RESET_ALL


# https://github.com/CravateRouge/bloodyAD/blob/main/bloodyAD/formatters/accesscontrol.py
# 2.4.7 SECURITY_INFORMATION
OWNER_SECURITY_INFORMATION = 0x00000001
GROUP_SECURITY_INFORMATION = 0x00000002
DACL_SECURITY_INFORMATION = 0x00000004
SACL_SECURITY_INFORMATION = 0x00000008
LABEL_SECURITY_INFORMATION = 0x00000010
UNPROTECTED_SACL_SECURITY_INFORMATION = 0x10000000
UNPROTECTED_DACL_SECURITY_INFORMATION = 0x20000000
PROTECTED_SACL_SECURITY_INFORMATION = 0x40000000
PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000
ATTRIBUTE_SECURITY_INFORMATION = 0x00000020
SCOPE_SECURITY_INFORMATION = 0x00000040
BACKUP_SECURITY_INFORMATION = 0x00010000

# https://docs.microsoft.com/en-us/windows/win32/api/iads/ne-iads-ads_rights_enum
ACCESS_FLAGS = {
    # Flag constants
    "GENERIC_READ": 0x80000000,
    "GENERIC_WRITE": 0x40000000,
    "GENERIC_EXECUTE": 0x20000000,
    "GENERIC_ALL": 0x10000000,
    "MAXIMUM_ALLOWED": 0x02000000,
    "ACCESS_SYSTEM_SECURITY": 0x01000000,
    "SYNCHRONIZE": 0x00100000,
    "FULL_CONTROL": 0x000F01FF,
    "WRITE_OWNER": 0x00080000,
    "WRITE_DACL": 0x00040000,
    "READ_CONTROL": 0x00020000,
    "DELETE": 0x00010000,
    # for ACCESS_ALLOWED_ACE types
    "ADS_RIGHT_DS_CONTROL_ACCESS": 0x00000100,
    "ADS_RIGHT_DS_CREATE_CHILD": 0x00000001,
    "ADS_RIGHT_DS_DELETE_CHILD": 0x00000002,
    "ADS_RIGHT_DS_READ_PROP": 0x00000010,
    "ADS_RIGHT_DS_WRITE_PROP": 0x00000020,
    "ADS_RIGHT_DS_SELF": 0x00000008,
}

# https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-addauditaccessobjectace
ACE_FLAGS = {
    # Flag constants
    "CONTAINER_INHERIT_ACE": 0x02,
    "FAILED_ACCESS_ACE_FLAG": 0x80,
    "INHERIT_ONLY_ACE": 0x08,
    "INHERITED_ACE": 0x10,
    "NO_PROPAGATE_INHERIT_ACE": 0x04,
    "OBJECT_INHERIT_ACE": 0x01,
    "SUCCESSFUL_ACCESS_ACE_FLAG": 0x40,
}

for handler in logging.root.handlers[:]:
    logging.root.removeHandler(handler)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%H:%M:%S',
    force=True
)
logger = logging.getLogger(__name__)


async def client(url, sid=None):
    conn_url = LDAPConnectionFactory.from_url(url)
    ldap_client = conn_url.get_client()
    _, err = await ldap_client.connect()
    if err is not None:
        raise err

    ACE_WITH_OBJECTTYPE = [
        0x05,  # ACCESS_ALLOWED_OBJECT_ACE_TYPE
        0x06,  # ACCESS_DENIED_OBJECT_ACE_TYPE
        0x07,  # SYSTEM_AUDIT_OBJECT_ACE_TYPE
        0x08,  # SYSTEM_ALARM_OBJECT_ACE_TYPE
    ]
    ACE_WITH_OBJECTTYPE = [
        0x05,  # ACCESS_ALLOWED_OBJECT_ACE_TYPE
        0x06,  # ACCESS_DENIED_OBJECT_ACE_TYPE
        0x07,  # SYSTEM_AUDIT_OBJECT_ACE_TYPE
        0x08,  # SYSTEM_ALARM_OBJECT_ACE_TYPE
        0x0B,  # ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE
        0x0C,  # ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE
        0x0F,  # SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE
        0x10,  # SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE
    ]

    data_list = []
    async for entry in ldap_client.get_all_objectacl():
        data = {}
        MSADsecurityInfo = entry[0]
        ntsecurity_descriptor = MSADsecurityInfo.nTSecurityDescriptor

        data.update({"DistinguishedName": MSADsecurityInfo.distinguishedName,
                     "ObjectSid": MSADsecurityInfo.objectSid})

        dacl = SR_SECURITY_DESCRIPTOR(ntsecurity_descriptor)["Dacl"]
        dacl_data = dacl["Data"]
        aces = []
        # breakpoint()
        for entry in dacl_data:
            permissions = []
            ace_type = entry["AceType"]
            ace_flags = entry["AceFlags"]
            type_name = entry["TypeName"]

            ace = entry["Ace"]
            mask = ace["Mask"]

            for name, flag in ACCESS_FLAGS.items():
                if mask.hasPriv(flag):
                    permissions.append(name)

            data_ace = {
                "TypeName": type_name,
                "AceType": ace_type,
                "AceFlags": ace_flags,
                "Mask": hex(int(str(mask), 16)),
                "SecurityIdentifier": ace["Sid"].formatCanonical(),
                "Permissions": ', '.join(permissions),
                "ObjectType": str(UUID(bytes_le=bytes(ace["ObjectType"]))) if ace_type in ACE_WITH_OBJECTTYPE and len(bytes(ace["ObjectType"])) == 16 else None,
                "InheritedObjectType": str(UUID(bytes_le=bytes(ace["InheritedObjectType"]))) if ace_type in ACE_WITH_OBJECTTYPE and len(bytes(ace["InheritedObjectType"])) == 16 else None,
            }
            aces.append(data_ace)
        data.update({"Aces": aces})
        data_list.append(data)
    data_objects = data_list
    await ldap_client.disconnect()
    return data_objects


class InteractiveShell(cmd.Cmd):
    prompt = "$ "
    intro = "Type 'help' to see available commands."

    def __init__(self, url, data, loop):
        super().__init__()
        self.url = url
        self.data = data
        self.loop = loop
        self.ldap_client = None
        self.connected = False
        self.object_cache = {}

    async def connect(self):
        conn_url = LDAPConnectionFactory.from_url(self.url)
        self.ldap_client = conn_url.get_client()
        _, err = await self.ldap_client.connect()
        if err is not None:
            print(f"Error de conexión: {err}")
            self.connected = False
        else:
            self.connected = True

    def do_help(self, arg):
        print("""Available commands:
refresh - Refresh ACL data
find_object_aces <username> - Search for ACEs for a specific user
exit - Exit interactive mode
""")

    def do_refresh(self, arg):
        """Actualizar datos de ACL"""
        self.data = self.loop.run_until_complete(client(self.url))

    def do_find_object_aces(self, arg):
        if not arg:
            logger.error("Input error: Username is required")
            return

        if not self.connected:
            logger.error(
                "Connection error: Unable to connect to the LDAP server")
            return

        self.loop.run_until_complete(self.async_find_object_aces(arg))

    def check_sid(self, sid):
        patron_sid = re.compile(
            r"^S-1-"
            r"(?:\d{1,19})"
            r"-(?:\d{1,10})(?:-\d{1,10}){1,14}$"
        )

        return bool(patron_sid.fullmatch(sid))

    def check_dn(self, dn):
        patron_rdn = re.compile(r'''
            ^                       
            (?:                    
                (?:CN|OU|DC|O|L|ST|C|UID)   
                =                   
                (?:\\.|[^,\\]+)*    
            )
            (?:                    
                ,                  
                (?:CN|OU|DC|O|L|ST|C|UID)=
                (?:\\.|[^,\\]+)*    
            )*                     
            $                       
        ''', re.VERBOSE | re.IGNORECASE)

        return bool(patron_rdn.fullmatch(dn))

    async def async_find_object_aces(self, arg1):
        ldap_object = None
        if self.check_sid(arg1):
            logger.info(f"Searching ACEs for SID: {arg1}")
            dn, err = await self.ldap_client.get_dn_for_objectsid(arg1)
            if err:
                logger.error(f"Error retrieving DN for SID {arg1}: {err}")
                return
            # check if the dn is group
            ldap_object, err = await self.ldap_client.get_group_by_dn(dn)
            if err:
                # check if the dn is user
                ldap_object, err = await self.ldap_client.get_user_by_dn(dn)
                if err:
                    logger.error(f"Error retrieving object for DN {dn}: {err}")
                    return
        # check if arg1 is dn
        elif self.check_dn(arg1):
            logger.info(f"Searching ACEs for DN: {arg1}")
            ldap_object, err = await self.ldap_client.get_group_by_dn(arg1)
            if err:
                ldap_object, err = await self.ldap_client.get_user_by_dn(arg1)
                if err:
                    logger.error(
                        f"Error retrieving object for DN {arg1}: {err}")
                    return
        # check if arg1 is samAccountnam,e
        else:
            ldap_filter = f"(&(objectClass=group)(sAMAccountName={arg1}))"

            async for entry, err in self.ldap_client.pagedsearch(query=ldap_filter, attributes=["*"]):
                ldap_object = MSADGroup.from_ldap(entry)

            if not ldap_object:
                ldap_filter = f"(&(objectClass=user)(sAMAccountName={arg1}))"
                async for entry, err in self.ldap_client.pagedsearch(query=ldap_filter, attributes=["*"]):
                    ldap_object = MSADUser.from_ldap(entry)

            # if not ldap_object:
            #     ldap_filter = f"(&(objectClass=container)(sAMAccountName={arg1}))"
            #     async for entry, err in self.ldap_client.pagedsearch(query=ldap_filter, attributes=["*"]):
            #         ldap_object = MSADContainer.from_ldap(entry)

            if not ldap_object:
                ldap_filter = f"(&(objectClass=computer)(sAMAccountName={arg1}))"
                async for entry, err in self.ldap_client.pagedsearch(query=ldap_filter, attributes=["*"]):
                    ldap_object = MSADMachine.from_ldap(entry)

            if not ldap_object:
                ldap_filter = f"(&(objectClass=dmsa)(sAMAccountName={arg1}))"
                async for entry, err in self.ldap_client.pagedsearch(query=ldap_filter, attributes=["*"]):
                    ldap_object = MSADDMSAUser.from_ldap(entry)
                    # objectName = entry.get("objectName", "Unknown")
                    # objectClass = entry.get(
                    #     "attributes", {}).get("objectClass", {})
                    # ldap_object = entry
                    # if "computer" in objectClass:
                    #     logger.info(f"Found computer: {objectName}")
                    #     ldap_object, err = await self.ldap_client.get_user_by_dn(objectName)
                    #     if err:
                    #         logger.error(
                    #             f"Error retrieving object for DN {arg1}: {err}")
                    #         return
                    #     breakpoint()
                    #     groups = ldap_object["memberOf"]
                    # if ldap_object is None:
                    #     logger.error(f"No object found for {arg1}")
                    #     return

                    # print(f"Object found")
                    # print(ldap_object)
                    # if groups is None:
                    #     groups = ldap_object["attributes"]["memberOf"]
                    # print(f"MemberOf: {groups}")
        # user
        sids = []
        memberOf = None
        object_sid = None
        members = []
        if isinstance(ldap_object, MSADUser):
            logger.info(f"Found user: {ldap_object.sAMAccountName}")
            object_sid = ldap_object.objectSid
            memberOf = ldap_object.memberOf
            if memberOf:
                for group in memberOf:
                    group_object, err = await self.ldap_client.get_group_by_dn(group)
                    if err:
                        logger.error(
                            f"Error retrieving group for DN {group}: {err}")
                    # members.append(group_object.member)
                    sids.append(group_object.objectSid)
        elif isinstance(ldap_object, MSADGroup):
            logger.info(f"Found group: {ldap_object.sAMAccountName}")
            object_sid = ldap_object.objectSid
            # members.append(group_object.member)
        # elif isinstance(ldap_object, MSADContainer):
        #     logger.info(f"Found container: {ldap_object.sAMAccountName}")
        elif isinstance(ldap_object, MSADMachine):
            logger.info(f"Found machine: {ldap_object.sAMAccountName}")
            object_sid = ldap_object.objectSid
        if memberOf:
            logger.info(f"MemberOf: {'; '.join(memberOf)}")
        sids = list(set([object_sid] + sids))

        # Find aces
        """{
            "DistinguishedName": MSADsecurityInfo.distinguishedName,
            "ObjectSid": MSADsecurityInfo.objectSid,
            "Aces": {
                        "TypeName": type_name,
                        "AceType": ace_type,
                        "AceFlags": ace_flags,
                        "Mask": hex(int(str(mask), 16)),
                        "SecurityIdentifier": ace["Sid"].formatCanonical(),
                        "Permissions": ', '.join(permissions),
                        "ObjectType": str(UUID(bytes_le=bytes(ace["ObjectType"]))) if ace_type in ACE_WITH_OBJECTTYPE and len(bytes(ace["ObjectType"])) == 16 else None,
                        "InheritedObjectType": str(UUID(bytes_le=bytes(ace["InheritedObjectType"]))) if ace_type in ACE_WITH_OBJECTTYPE and len(bytes(ace["InheritedObjectType"])) == 16 else None,
                    }
        }"""
        ace_counter = 0
        objects = []

        while True:
            new_sids = []
            for entry in self.data:
                for ace in entry.get("Aces", []):
                    for sid in sids:
                        if ace["SecurityIdentifier"] == sid:
                            ace_counter += 1

                            print(COLOR_HEADER + "\n" + "=" * 80 + COLOR_RESET)
                            print(f"{COLOR_ACE}ACE #{ace_counter}{COLOR_RESET}")
                            print(
                                f"{COLOR_DN}Object DN: {COLOR_VALUE}{entry['DistinguishedName']}{COLOR_RESET}")
                            print(
                                f"{COLOR_SID}Object SID: {COLOR_VALUE}{entry['ObjectSid']}{COLOR_RESET}")
                            print(COLOR_HEADER + "-" * 80 + COLOR_RESET)
                            print(
                                f"{COLOR_ACE}  ACE Type: {COLOR_VALUE}{ace.get('AceType')}{COLOR_RESET}")
                            print(
                                f"{COLOR_ACE}  SID: {COLOR_VALUE}{ace.get('SecurityIdentifier')}{COLOR_RESET}")
                            print(
                                f"{COLOR_ACE}  Permissions: {COLOR_VALUE}{ace.get('Permissions')}{COLOR_RESET}")
                            print(
                                f"{COLOR_ACE}  Object Type: {COLOR_VALUE}{ace.get('ObjectType') or '-'}{COLOR_RESET}")
                            print(
                                f"{COLOR_ACE}  Inherited Type: {COLOR_VALUE}{ace.get('InheritedObjectType') or '-'}{COLOR_RESET}")

                            new_sids.append(entry['ObjectSid'])
                            objects.append({
                                "From": sid,
                                "To": entry['ObjectSid'] if entry['ObjectSid'] else entry["DistinguishedName"],
                                "Permissions": ace.get('Permissions'),
                                "ObjectType": ace.get('ObjectType'),
                            })
            sids = list(set(new_sids))
            if len(sids) == 0:
                print(COLOR_HEADER + "\n" + "=" * 80)
                print(
                    f"ACL expansion complete. Total ACEs found: {ace_counter}")
                print("=" * 80 + COLOR_RESET)
                break
        merged_objects = defaultdict(
            lambda: {"Permissions": set(), "ObjectType": None})

        for obj in objects:
            key = (obj["From"], obj["To"])

            if obj["Permissions"]:
                if isinstance(obj["Permissions"], str):
                    merged_objects[key]["Permissions"].update(
                        [obj["Permissions"]])
                else:
                    merged_objects[key]["Permissions"].update(
                        obj["Permissions"])

            if not merged_objects[key]["ObjectType"] and obj.get("ObjectType"):
                merged_objects[key]["ObjectType"] = obj["ObjectType"]

        final_objects = []
        for (from_sid, to_sid), data in merged_objects.items():
            final_objects.append({
                "From": from_sid,
                "To": to_sid,
                "Permissions": list(data["Permissions"]),
                "ObjectType": data["ObjectType"]
            })
        objects = final_objects

        tree = {}
        sid_to_name = {}

        for entry in objects:
            if entry["From"] not in sid_to_name:
                try:
                    dn, err = await self.ldap_client.get_dn_for_objectsid(entry["From"])
                    if not err:
                        obj, err = await self.ldap_client.get_group_by_dn(dn)
                        if err:
                            obj, err = await self.ldap_client.get_user_by_dn(dn)
                        if obj:
                            sid_to_name[entry["From"]] = obj.distinguishedName
                except Exception as e:
                    logger.error(
                        f"Error resolving SID {entry['From']}: {str(e)}")
                    sid_to_name[entry["From"]] = f"Unknown ({entry['From']})"

            if entry["To"] not in sid_to_name:
                if self.check_sid(entry["To"]):
                    try:
                        dn, err = await self.ldap_client.get_dn_for_objectsid(entry["To"])
                        if not err:
                            obj, err = await self.ldap_client.get_group_by_dn(dn)
                            if err:
                                obj, err = await self.ldap_client.get_user_by_dn(dn)
                            if obj:
                                sid_to_name[entry["To"]
                                            ] = obj.distinguishedName
                    except Exception as e:
                        logger.error(
                            f"Error resolving SID {entry['To']}: {str(e)}")
                        sid_to_name[entry["To"]] = f"Unknown ({entry['To']})"
                else:
                    sid_to_name[entry["To"]] = entry["To"]
        root_name = sid_to_name.get(object_sid, object_sid)

        def print_color(text, color=None, bold=False, return_str=False):
            if has_colorama and color:
                color_code = getattr(Fore, color.upper(), '')
                style_code = Style.BRIGHT if bold else ''
                result = f"{style_code}{color_code}{text}{Style.RESET_ALL}"
            else:
                result = text

            if return_str:
                return result
            else:
                print(result)
        GUID_MAP = {**SCHEMA_OBJECTS, **EXTENDED_RIGHTS}

        def resolve_guid(guid):
            if not guid:
                return None
            return GUID_MAP.get(guid.lower(), guid)
        tree = {}
        for entry in objects:
            from_node = sid_to_name[entry["From"]]
            to_node = sid_to_name[entry["To"]]

            if from_node not in tree:
                tree[from_node] = []

            resolved_type = resolve_guid(entry["ObjectType"])

            tree[from_node].append({
                "target": to_node,
                "permissions": entry["Permissions"],
                "object_type": resolved_type 
            })

        def print_clean_tree(root, depth=0, prefix="", is_last=False, visited=None):
            if visited is None:
                visited = set()

            if root in visited:
                return
            visited.add(root)

            if depth > 0:
                connector = "└── " if is_last else "├── "
                print(
                    f"{prefix}{connector}{print_color(root, 'cyan', True, return_str=True)}")
                prefix += "    " if is_last else "│   "

            if root in tree:
                children = tree[root]
                for i, child in enumerate(children):
                    child_is_last = i == len(children) - 1

                    perm_text = print_color(
                        f"[{', '.join(child['permissions'])}]",
                        "magenta",
                        True,
                        return_str=True
                    )

                    arrow = print_color(" → ", "white", False, return_str=True)

                    perm_connector = "└── " if child_is_last else "├── "
                    perm_line = f"{prefix}{perm_connector}{perm_text}{arrow}"

                    if child['object_type']:
                        obj_type = child['object_type']
                        if len(obj_type) > 30:
                            obj_type = obj_type[:27] + "..."
                        obj_text = print_color(
                            f"({obj_type})", "yellow", False, return_str=True)
                        perm_line += obj_text
                    else:
                        perm_line += print_color("(No Object Type)", "red", False, return_str=True)
                    print(perm_line)

                    print_clean_tree(
                        child["target"],
                        depth + 1,
                        prefix + ("    " if child_is_last else "│   "),
                        child_is_last,
                        visited
                    )
            elif depth == 0:
                print_color(
                    f"{prefix}└── No permission relationships were found", "yellow")

        print("\n" + "=" * 80)
        print_color("PERMISSION RELATIONS WITH RESOLVED OBJECT TYPES",
                    "yellow", bold=True)
        print("=" * 80)

        print_color(root_name, "green", bold=True)
        print_clean_tree(root_name)

    def do_exit(self, arg):
        if self.connected:
            self.loop.run_until_complete(self.ldap_client.disconnect())
            logger.info("Disconnected from LDAP server.")
        return True

    def do_EOF(self, arg):
        return self.do_exit(arg)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--auth', help='Autentication URL')
    args = parser.parse_args()
    if args.auth:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        data = loop.run_until_complete(client(args.auth))
        # data = {}
        # Serializing json
        # with open('data.json', 'r') as openfile:
        #     data = json.load(openfile)
        shell = InteractiveShell(args.auth, data, loop)
        loop.run_until_complete(shell.connect())
        shell.cmdloop()
