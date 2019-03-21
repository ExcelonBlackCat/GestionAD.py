#!/usr/bin/python
#================================================================================================================#
#
#          FILE:  GestionAD.py
#
#   DESCRIPTION:  Gestion de l'Active Directory
#
#         USAGE:  ./GestionAD.py TYPE(test,mdp,creation,ect..) NOM DE COMPTE DONNEE(pwd,active,prenom,nom,ect..)
#
#       OPTIONS:  arg1=TYPE arg2=NOM DU COMPTE arg3=DONNEE SELON LE TYPE
#  REQUIREMENTS:  ---
#          BUGS:  ---
#         NOTES:  ---
#        AUTHOR:  Lucas DEFOSSEZ
#       COMPANY:
#       VERSION:  1.0
#       CREATED:  17/01/2018 11:30:10
#      REVISION:  02/02/2019 15:15:46
#================================================================================================================#

import ldap
import ldap.modlist as modlist
import sys
import uuid

ADMIN_PWD = 'password'
ADMIN_BIND = 'user'
LDAP_ADDR = 'ldaps://ipserver:636' #connexion sur le port securise
LDAP_BASE = 'DC=DOMAIN,DC=COM'

# Initialisation de la connection LDAP
try:
    ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT,0)
    ldap.protocol_version=ldap.VERSION3
    ldap.set_option(ldap.OPT_REFERRALS, 0)
    l=ldap.initialize(LDAP_ADDR)
except ldap.LDAPError as e:
    print ("ldap error: {0}".format(e))
    sys.exit(1)

# Connection au LDAP
try:
    l.bind_s(ADMIN_BIND, ADMIN_PWD)
except ldap.LDAPError as e:
    print ("ldap error: {0}".format(e))
    sys.exit(1)

# arg 1 mod d'utilisation du script (test,mdp,activation,creation,....)
if (len(sys.argv) < 2):
    print (".: Veuilliez choisir un des choix ci-dessous :.")
    print ("+----------+-----------+----------+-----+------------+--------+----------+----------+--------------+----------+---------+")
    print ("| TestUser | TestGroup | Creation | MDP | Activation | Reinit | GroupAdd | GroupDel | ReActivation | DumpUser | GetGuid |")
    print ("+----------+-----------+----------+-----+------------+--------+----------+----------+--------------+----------+---------+")
    sys.exit(1)
# arg 2 nom de compte :: arg 3 On ou Off
if str(sys.argv[1]).lower()=="activation":
    #on vas toujours compte les arguments en +1, car l'argument 1 est le nom du script contrairement au bash (l'argument 3 compte comme le 4eme)
    if (len(sys.argv) != 4):
        print ("./GestionAD.py 'activation' 'Nom de Compte' 'On ou Off'")
        sys.exit(1)

    #au niveau de l'AD, il ne connais que 512 ou 514 du coup on traduit pour nous les 'H'ommes
    if str(sys.argv[3]).lower()=="on":
        ATT_VALUE = "512"
    elif str(sys.argv[3]).lower()=="off":
        ATT_VALUE = "514"
    else:
        print ("ON or OFF")
        sys.exit(1)

    # ici on vas chercher notre utilisateur afin de retourner les bonnes informations, on evite de laisser entrer murphy trop facilement
    try:
        USER_DN = "".join(('userPrincipalName=',str(sys.argv[2]).lower(),'@domain.com'))
        ldap_result_id=l.search(LDAP_BASE,ldap.SCOPE_SUBTREE,USER_DN,None)
        result = []
        while 1:
            result_type, result_data = l.result(ldap_result_id, 0)
            if (result_data == []):
                break
            elif result_type == ldap.RES_SEARCH_ENTRY:
                result.append(result_data)
    except ldap.LDAPError as e:
        print ("ldap error: {0}".format(e))
        sys.exit(1)
    #on recupere le nom distingue (un equivalent d'UID, c'est un nom unique), son nom complet et tout ses groupes
    else:
        for i in range(len(result)):
            for entry in result[i]:
                USER_DN = entry[1]['distinguishedName'][0]
                CN = entry[1]['cn'][0]
                GROUPS = entry[1]['memberOf']

    ATTR = "userAccountControl"
    userAccountControl = [(ldap.MOD_REPLACE, ATTR, [ATT_VALUE])]
    try:
        l.modify_s(USER_DN, userAccountControl)
    except ldap.LDAPError as e:
        print ("ldap error: {0}".format(e))
        sys.exit(1)

    #si on desactive on retire l'utilisateur de tout ses groupes
    if str(sys.argv[3]).lower()=="off":
        for i in range(len(GROUPS)):
            try:
                GROUP_DN = GROUPS[i].split(",")[0]
                ldap_result_id=l.search(LDAP_BASE,ldap.SCOPE_SUBTREE,GROUP_DN,None)
                result = []
                while 1:
                    result_type, result_data = l.result(ldap_result_id,0)
                    if (result_data == []):
                        break
                    elif result_type == ldap.RES_SEARCH_ENTRY:
                        result.append(result_data)
            except ldap.LDAPError as e:
                print ("ldap error: {0}".format(e))
                sys.exit(1)
            else:
                for i in range(len(result)):
                    for entry in result[i]:
                        GROUP_DN = entry[1]['distinguishedName'][0]
                        usersMember = entry[1]['member']
                try:
                    usersMember.remove(USER_DN)
                    add_member = [(ldap.MOD_REPLACE, "member", usersMember)]
                    l.modify_s(GROUP_DN, add_member)
                except ldap.LDAPError as e:
                    print ("ldap error: {0}".format(e))
                    sys.exit(1)


# arg 2 nom de compte :: arg 3 prenom :: arg 4 nom :: arg 5 service
elif str(sys.argv[1]).lower()=="creation":
    if (len(sys.argv) != 6):
        print ("./GestionAD.py 'creation' 'Nom de Compte' 'Prenom' 'Nom' 'Service'")
        sys.exit(1)

    #on initialize le mdp et on le met au format AD
    unipwd = unicode("\"" + "password" + "\"", "iso-8859-1")
    pwd = unipwd.encode("utf-16-le")
    CN = "".join((str(sys.argv[3]).lower(),' ',str(sys.argv[4]).lower()))

    #on cherche le groupe
    try:
        GROUP_DN = "".join(('CN=',str(sys.argv[5]).lower()))
        ldap_result_id=l.search(LDAP_BASE,ldap.SCOPE_SUBTREE,GROUP_DN,None)
        results = []
        while 1:
            result_type, result_data = l.result(ldap_result_id,0)
            if (result_data == []):
                break
            elif result_type == ldap.RES_SEARCH_ENTRY:
                results.append(result_data)
    except ldap.LDAPError as e:
        print ("ldap error: {0}".format(e))
        sys.exit(1)
    else:
        for i in range(len(results)):
            for entry in results[i]:
                GROUP = entry[1]['cn'][0]

    #maintenant que l'on sait ou va etre notre user ,dans quel groupe, avec quel mdp. On initie un tableau avec toutes les informations
    USER_DN = "".join(('CN=',CN,OU,',OU=Users,OU=SUBDOMAIN,DC=DOMAIN,DC=COM'))
    AD_USER = {
        'objectClass': ['top', 'person', 'organizationalPerson', 'user'],
        'cn': CN,
        'givenName': str(sys.argv[3]).lower(),
        'displayName': CN,
        'name' : CN,
        'sAMAccountName': str(sys.argv[2]).lower(),
        'pwdLastSet' : '0',
        'sn': str(sys.argv[4]).lower(),
        'userAccountControl': '514',  # 514 correspond a un compte desactive, mais on ne peut pas cree directement en active (raison:windows)
        'userPrincipalName': "".join((str(sys.argv[2]).lower(),'@domain.com')),
        'mail': "".join((str(sys.argv[2]).lower(), '@domain.com')),
        'unicodePwd': pwd,
        'description': "".join(('Compte Active Directory de ',CN)),
    }
    ldif = modlist.addModlist(AD_USER)

    # on essaye de cree le compte
    try:
        l.add_s(USER_DN, ldif)
    except ldap.LDAPError as e:
        print ("ldap error: {0}".format(e))
        sys.exit(1)
# arg 2 nom du compte :: arg 3 nouveau mdp
elif str(sys.argv[1]).lower()=="mdp":
    if (len(sys.argv) != 4):
        print ("./GestionAD.py 'mdp' 'Nom de Compte' 'Mot de Passe'")
        sys.exit(1)

    NEW_PWD = str(sys.argv[3])
    try:
        USER_DN = "".join(('userPrincipalName=',str(sys.argv[2]).lower(),'@domain.com'))
        ldap_result_id=l.search(LDAP_BASE,ldap.SCOPE_SUBTREE,USER_DN,None)
        result = []
        while 1:
            result_type, result_data = l.result(ldap_result_id, 0)
            if (result_data == []):
                break
            elif result_type == ldap.RES_SEARCH_ENTRY:
                result.append(result_data)
    except ldap.LDAPError as e:
        print ("ldap error: {0}".format(e))
        sys.exit(1)
    else:
        for i in range(len(result)):
            for entry in result[i]:
                USER_DN = entry[1]['distinguishedName'][0]

        # Set AD
        PASSWORD_ATTR = "unicodePwd"
        unicode_pass = unicode("\"" + NEW_PWD + "\"", "iso-8859-1")
        password_value = unicode_pass.encode("utf-16-le")
        add_pass = [(ldap.MOD_REPLACE, PASSWORD_ATTR, [password_value])]

        # Replace password
        try:
            l.modify_s(USER_DN, add_pass)
        except ldap.LDAPError as e:
            print ("ldap error: {0}".format(e))
            sys.exit(1)

# arg 2 nom du compte
# ici on verifie juste si le compte existe et on retourne toutes les informations disponible
elif str(sys.argv[1]).lower()=="testuser":
    if (len(sys.argv) != 3):
        print ("./GestionAD.py 'testuser' 'Nom de Compte'")
        sys.exit(1)

    try:
        USER_DN = "".join(('userPrincipalName=',str(sys.argv[2]).lower(),'@domain.com'))
        ldap_result_id=l.search(LDAP_BASE,ldap.SCOPE_SUBTREE,USER_DN,None)
        result = []
        while 1:
            result_type, result_data = l.result(ldap_result_id,0)
            if (result_data == []):
                break
            elif result_type == ldap.RES_SEARCH_ENTRY:
                result.append(result_data)
    except ldap.LDAPError as e:
        print ("ldap error: {0}".format(e))
        sys.exit(1)
    else:
        print (result)

#arg 2 nom du compte
elif str(sys.argv[1]).lower()=="reinit":
    if (len(sys.argv) != 3):
        print ("./GestionAD.py 'reinit' 'Nom de Compte'")
        sys.exit(1)

    try:
        USER_DN = "".join(('userPrincipalName=',str(sys.argv[2]).lower(),'@domain.com'))
        ldap_result_id=l.search(LDAP_BASE,ldap.SCOPE_SUBTREE,USER_DN,None)
        result = []
        while 1:
            result_type, result_data = l.result(ldap_result_id,0)
            if (result_data == []):
                break
            elif result_type == ldap.RES_SEARCH_ENTRY:
                result.append(result_data)
    except ldap.LDAPError as e:
        print ("ldap error: {0}".format(e))
        sys.exit(1)
    else:
        for i in range(len(result)):
            for entry in result[i]:
                USER_DN = entry[1]['distinguishedName'][0]

        PASSWORD_ATTR = "unicodePwd"
        unicode_pass = unicode("\"" + "Password" + "\"", "iso-8859-1")
        password_value = unicode_pass.encode("utf-16-le")
        add_pass = [(ldap.MOD_REPLACE, PASSWORD_ATTR, [password_value])]

        #on change le mdp
        try:
            l.modify_s(USER_DN, add_pass)
        except ldap.LDAPError as e:
            print ("ldap error: {0}".format(e))
            sys.exit(1)
        else:
            add_ls= [(ldap.MOD_REPLACE, 'pwdLastSet', '0')]

            #on indique qu'il faudrat changer de mdp a la prochaine connexion
            try:
               l.modify_s(USER_DN, add_ls)
            except ldap.LDAPError as e:
                print ("ldap error: {0}".format(e))
                sys.exit(1)

elif str(sys.argv[1]).lower()=="testgroup":
    if (len(sys.argv) != 3):
        print ("./GestionAD.py 'testgroup' 'Nom du Groupe'")
        sys.exit(1)

    try:
        GROUP_DN = "".join(('CN=',str(sys.argv[2]).lower()))
        ldap_result_id=l.search(LDAP_BASE,ldap.SCOPE_SUBTREE,GROUP_DN,None)
        results = []
        while 1:
            result_type, result_data = l.result(ldap_result_id,0)
            if (result_data == []):
                break
            elif result_type == ldap.RES_SEARCH_ENTRY:
                results.append(result_data)
    except ldap.LDAPError as e:
        print ("ldap error: {0}".format(e))
        sys.exit(1)
    else:
        print (results)

elif str(sys.argv[1]).lower()=="groupadd":
    if (len(sys.argv) != 4):
        print ("./GestionAD.py 'groupadd' 'Nom du Compte' 'Nom du Groupe'")
        sys.exit(1)

    try:
        USER_DN = "".join(('userPrincipalName=',str(sys.argv[2]).lower(),'@domain.com'))
        ldap_result_id=l.search(LDAP_BASE,ldap.SCOPE_SUBTREE,USER_DN,None)
        result = []
        while 1:
            result_type, result_data = l.result(ldap_result_id,0)
            if (result_data == []):
                break
            elif result_type == ldap.RES_SEARCH_ENTRY:
                result.append(result_data)
    except ldap.LDAPError as e:
        print ("ldap error: {0}".format(e))
        sys.exit(1)
    else:
        for i in range(len(result)):
            for entry in result[i]:
                 userdistinguishedName = entry[1]['distinguishedName'][0]
        try:
            GROUP_DN = "".join(('CN=',str(sys.argv[3]).lower()))
            ldap_result_id=l.search(LDAP_BASE,ldap.SCOPE_SUBTREE,GROUP_DN,None)
            result = []
            while 1:
                result_type, result_data = l.result(ldap_result_id,0)
                if (result_data == []):
                    break
                elif result_type == ldap.RES_SEARCH_ENTRY:
                    result.append(result_data)
        except ldap.LDAPError as e:
            print ("ldap error: {0}".format(e))
            sys.exit(1)
        else:
            for i in range(len(result)):
                for entry in result[i]:
                    GROUP_DN = entry[1]['distinguishedName'][0]
                    usersMember = entry[1]['member']
            try:
                usersMember.insert(0,userdistinguishedName)
                add_member = [(ldap.MOD_REPLACE, "member", usersMember)]
                l.modify_s(GROUP_DN, add_member)
            except ldap.LDAPError as e:
                print ("ldap error: {0}".format(e))
                sys.exit(1)

elif str(sys.argv[1]).lower()=="groupdel":
    if (len(sys.argv) != 4):
        print ("./GestionAD.py 'groupdel' 'Nom du Compte' 'Nom du Groupe'")
        sys.exit(1)

    try:
        USER_DN = "".join(('userPrincipalName=',str(sys.argv[2]).lower(),'@domain.com'))
        ldap_result_id=l.search(LDAP_BASE,ldap.SCOPE_SUBTREE,USER_DN,None)
        result = []
        while 1:
            result_type, result_data = l.result(ldap_result_id,0)
            if (result_data == []):
                break
            elif result_type == ldap.RES_SEARCH_ENTRY:
                result.append(result_data)
    except ldap.LDAPError as e:
        print ("ldap error: {0}".format(e))
        sys.exit(1)
    else:
        for i in range(len(result)):
            for entry in result[i]:
                 userdistinguishedName = entry[1]['distinguishedName'][0]
        try:
            GROUP_DN = "".join(('CN=',str(sys.argv[3]).lower()))
            ldap_result_id=l.search(LDAP_BASE,ldap.SCOPE_SUBTREE,GROUP_DN,None)
            result = []
            while 1:
                result_type, result_data = l.result(ldap_result_id,0)
                if (result_data == []):
                    break
                elif result_type == ldap.RES_SEARCH_ENTRY:
                    result.append(result_data)
        except ldap.LDAPError as e:
            print ("ldap error: {0}".format(e))
            sys.exit(1)
        else:
            for i in range(len(result)):
                for entry in result[i]:
                    GROUP_DN = entry[1]['distinguishedName'][0]
                    usersMember = entry[1]['member']
            try:
                usersMember.remove(userdistinguishedName)
                add_member = [(ldap.MOD_REPLACE, "member", usersMember)]
                l.modify_s(GROUP_DN, add_member)
            except ldap.LDAPError as e:
                print ("ldap error: {0}".format(e))
                sys.exit(1)

# arg 2 nom du compte
# ici on verifie juste si le compte existe et on retourne toutes les informations disponible
elif str(sys.argv[1]).lower()=="dumpuser":
    if (len(sys.argv) != 2):
        print ("./GestionAD.py 'dumpuser'")
        sys.exit(1)

    try:
        USER_DN = "".join(('userPrincipalName=','*','@domain.com'))
        ldap_result_id=l.search(LDAP_BASE,ldap.SCOPE_SUBTREE,USER_DN,None)
        result = []
        while 1:
            result_type, result_data = l.result(ldap_result_id,0)
            if (result_data == []):
                break
            elif result_type == ldap.RES_SEARCH_ENTRY:
                result.append(result_data)
    except ldap.LDAPError as e:
        print ("ldap error: {0}".format(e))
        sys.exit(1)
    else:
        for i in range(len(result)):
            for entry in result[i]:
                print("".join((str(entry[1]['sAMAccountName']),str(entry[1]['userAccountControl']))))

elif str(sys.argv[1]).lower()=="getguid":
    if (len(sys.argv) != 3):
        print ("./GestionAD.py 'GetGuid' 'Nom de Compte'")
        sys.exit(1)

    try:
        USER_DN = "".join(('userPrincipalName=',str(sys.argv[2]).lower(),'@domain.com'))
        ldap_result_id=l.search(LDAP_BASE,ldap.SCOPE_SUBTREE,USER_DN,None)
        result = []
        while 1:
            result_type, result_data = l.result(ldap_result_id,0)
            if (result_data == []):
                break
            elif result_type == ldap.RES_SEARCH_ENTRY:
                result.append(result_data)
    except ldap.LDAPError as e:
        print ("ldap error: {0}".format(e))
        sys.exit(1)
    else:
        for i in range(len(result)):
            for entry in result[i]:
                object_guid = b"".join(entry[1]['objectGUID'][0])
                guid = uuid.UUID(bytes=object_guid)
                print(guid.hex)

elif str(sys.argv[1]).lower()=="reactivation":
    if (len(sys.argv) != 4):
        print ("./GestionAD.py 'ReActivation' 'Nom du Compte' 'Service'")
        sys.exit(1)

    # ici on vas chercher notre utilisateur afin de retourner les bonnes informations, on evite de laisser entrer murphy trop facilement
    try:
        USER_DN = "".join(('userPrincipalName=',str(sys.argv[2]).lower(),'@domain.com'))
        ldap_result_id=l.search(LDAP_BASE,ldap.SCOPE_SUBTREE,USER_DN,None)
        result = []
        while 1:
            result_type, result_data = l.result(ldap_result_id, 0)
            if (result_data == []):
                break
            elif result_type == ldap.RES_SEARCH_ENTRY:
                result.append(result_data)
    except ldap.LDAPError as e:
        print ("ldap error: {0}".format(e))
        sys.exit(1)
    #on recupere le nom distingue (un equivalent d'UID, c'est un nom unique) et son nom complet
    else:
        for i in range(len(result)):
            for entry in result[i]:
                USER_DN = entry[1]['distinguishedName'][0]
                CN = entry[1]['cn'][0]

        #on verifie si il est present dans les comptes desactives
        if 'comptes d' in str(USER_DN).lower():
            #on cherche le groupe
            try:
                GROUP_DN = "".join(('CN=',str(sys.argv[3]).lower()))
                ldap_result_id=l.search(LDAP_BASE,ldap.SCOPE_SUBTREE,GROUP_DN,None)
                results = []
                while 1:
                    result_type, result_data = l.result(ldap_result_id,0)
                    if (result_data == []):
                        break
                    elif result_type == ldap.RES_SEARCH_ENTRY:
                        results.append(result_data)
            except ldap.LDAPError as e:
                print ("ldap error: {0}".format(e))
                sys.exit(1)
            else:
                for i in range(len(results)):
                    for entry in results[i]:
                        GROUP = entry[1]['cn'][0]


            #on le met dans l'OU qui correspond au groupe
            #on retire le premier charactere (une virgule)
            OU=OU[1:]
            OU = "".join((OU,',OU=Users,OU=SUBDOMAIN,DC=DOMAIN,DC=COM'))
            CN = "".join(('CN=',CN))
            try:
                l.rename_s(USER_DN, CN, OU)
            except ldap.LDAPError as e:
                print ("ldap error: {0}".format(e))
                sys.exit(1)
        else:
            sys.exit(1)

else:
    print (".: Veuilliez choisir un des choix ci-dessous :.")
    print ("+----------+-----------+----------+-----+------------+--------+----------+----------+--------------+----------+---------+")
    print ("| TestUser | TestGroup | Creation | MDP | Activation | Reinit | GroupAdd | GroupDel | ReActivation | DumpUser | GetGuid |")
    print ("+----------+-----------+----------+-----+------------+--------+----------+----------+--------------+----------+---------+")
    sys.exit(1)

# close connexion
l.unbind()
