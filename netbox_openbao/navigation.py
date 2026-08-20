from netbox.plugins import PluginMenu, PluginMenuButton, PluginMenuItem

credentials = PluginMenuItem(
    link='plugins:netbox_openbao:credential_list',
    link_text='Credentials',
    permissions=['netbox_openbao.view_credential'],
    buttons=(
        PluginMenuButton(
            link='plugins:netbox_openbao:credential_add',
            title='Add',
            icon_class='mdi mdi-plus-thick',
            permissions=['netbox_openbao.add_credential'],
        ),
    ),
)

assignments = PluginMenuItem(
    link='plugins:netbox_openbao:credentialassignment_list',
    link_text='Assignments',
    permissions=['netbox_openbao.view_credentialassignment'],
    buttons=(
        PluginMenuButton(
            link='plugins:netbox_openbao:credentialassignment_add',
            title='Add',
            icon_class='mdi mdi-plus-thick',
            permissions=['netbox_openbao.add_credentialassignment'],
        ),
    ),
)

policies = PluginMenuItem(
    link='plugins:netbox_openbao:credentialpolicy_list',
    link_text='Policies',
    permissions=['netbox_openbao.view_credentialpolicy'],
    buttons=(
        PluginMenuButton(
            link='plugins:netbox_openbao:credentialpolicy_add',
            title='Add',
            icon_class='mdi mdi-plus-thick',
            permissions=['netbox_openbao.add_credentialpolicy'],
        ),
    ),
)

engines = PluginMenuItem(
    link='plugins:netbox_openbao:secretengine_list',
    link_text='Secret engines',
    permissions=['netbox_openbao.view_secretengine'],
    buttons=(
        PluginMenuButton(
            link='plugins:netbox_openbao:secretengine_add',
            title='Add',
            icon_class='mdi mdi-plus-thick',
            permissions=['netbox_openbao.add_secretengine'],
        ),
    ),
)

type_schemas = PluginMenuItem(
    link='plugins:netbox_openbao:credentialtypeschema_list',
    link_text='Credential types',
    permissions=['netbox_openbao.view_credentialtypeschema'],
    buttons=(
        PluginMenuButton(
            link='plugins:netbox_openbao:credentialtypeschema_add',
            title='Add',
            icon_class='mdi mdi-plus-thick',
            permissions=['netbox_openbao.add_credentialtypeschema'],
        ),
    ),
)

access_logs = PluginMenuItem(
    link='plugins:netbox_openbao:credentialaccesslog_list',
    link_text='Access log',
    permissions=['netbox_openbao.view_credentialaccesslog'],
)

menu = PluginMenu(
    label='OpenBao',
    groups=(
        ('Credentials', (credentials, assignments)),
        ('Configuration', (policies, engines, type_schemas)),
        ('Audit', (access_logs,)),
    ),
    icon_class='mdi mdi-shield-key',
)
