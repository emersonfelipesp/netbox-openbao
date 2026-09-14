from netbox.plugins import PluginMenu, PluginMenuButton, PluginMenuItem

clusters = PluginMenuItem(
    link='plugins:netbox_openbao:openbaocluster_list',
    link_text='Clusters',
    permissions=['netbox_openbao.view_openbaocluster'],
    buttons=(
        PluginMenuButton(
            link='plugins:netbox_openbao:openbaocluster_add',
            title='Add',
            icon_class='mdi mdi-plus-thick',
            permissions=['netbox_openbao.add_openbaocluster'],
        ),
    ),
)

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

administration_logs = PluginMenuItem(
    link='plugins:netbox_openbao:openbaoadministrationlog_list',
    link_text='Administration log',
    permissions=['netbox_openbao.view_openbaoadministrationlog'],
)

procedure_runs = PluginMenuItem(
    link='plugins:netbox_openbao:openbaoprocedurerun_list',
    link_text='Procedure runs',
    permissions=['netbox_openbao.view_openbaoprocedurerun'],
)

settings_item = PluginMenuItem(
    link='plugins:netbox_openbao:openbaosettings_list',
    link_text='Settings',
    permissions=['netbox_openbao.view_openbaosettings'],
    buttons=(
        # The seeding migration deliberately leaves the row absent on a
        # deployment running the defaults, so a fresh install lands on an empty
        # list with no discoverable way in. The permission gate is not enough on
        # its own — the form also refuses a second row, because reaching this
        # page on a configured install would otherwise hit the unique
        # constraint and surface as a server error rather than a message.
        PluginMenuButton(
            link='plugins:netbox_openbao:openbaosettings_add',
            title='Configure',
            icon_class='mdi mdi-plus-thick',
            permissions=['netbox_openbao.add_openbaosettings'],
        ),
    ),
)

menu = PluginMenu(
    label='OpenBao',
    groups=(
        ('Credentials', (credentials, assignments)),
        ('Administration', (clusters,)),
        ('Configuration', (policies, engines, type_schemas, settings_item)),
        ('Audit', (access_logs, administration_logs, procedure_runs)),
    ),
    icon_class='mdi mdi-shield-key',
)
