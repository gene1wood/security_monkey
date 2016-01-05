#     Copyright 2014 Netflix, Inc.
#
#     Licensed under the Apache License, Version 2.0 (the "License");
#     you may not use this file except in compliance with the License.
#     You may obtain a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#     Unless required by applicable law or agreed to in writing, software
#     distributed under the License is distributed on an "AS IS" BASIS,
#     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#     See the License for the specific language governing permissions and
#     limitations under the License.
"""
.. module: security_monkey
    :platform: Unix

.. version:: $$VERSION$$
.. moduleauthor:: Patrick Kelley <patrick@netflix.com>

"""
### FLASK ###
from flask import Flask
from flask import render_template
from flask.ext.sqlalchemy import SQLAlchemy
app = Flask(__name__)
app.config.from_envvar("SECURITY_MONKEY_SETTINGS")
db = SQLAlchemy(app)

# For ELB and/or Eureka
@app.route('/healthcheck')
def healthcheck():
    return 'ok'


### LOGGING ###
import logging
from logging import Formatter
from logging.handlers import RotatingFileHandler
from logging import StreamHandler
handler = RotatingFileHandler(app.config.get('LOG_FILE'), maxBytes=10000000, backupCount=100)
handler.setFormatter(
    Formatter('%(asctime)s %(levelname)s: %(message)s '
              '[in %(pathname)s:%(lineno)d]')
)
handler.setLevel(app.config.get('LOG_LEVEL'))
app.logger.setLevel(app.config.get('LOG_LEVEL'))
app.logger.addHandler(handler)
app.logger.addHandler(StreamHandler())

### Flask-WTF CSRF Protection ###
from flask_wtf.csrf import CsrfProtect

csrf = CsrfProtect()
csrf.init_app(app)

@csrf.error_handler
def csrf_error(reason):
    app.logger.debug("CSRF ERROR: {}".format(reason))
    return render_template('csrf_error.json', reason=reason), 400


### Flask-Login ###
from flask.ext.login import LoginManager
login_manager = LoginManager()
login_manager.init_app(app)

from security_monkey.datastore import User, Role


@login_manager.user_loader
def load_user(email):
    """
    For Flask-Login, returns the user object given the userid.
    :return: security_monkey.datastore.User object
    """
    app.logger.info("Inside load_user!")
    user = User.query.filter(User.email == email).first()
    if not user:
        user = User(email=email)
        db.session.add(user)
        db.session.commit()
        db.session.close()
        user = User.query.filter(User.email == email).first()
    return user


if app.config.get('USE_SAML'):
    from saml import login_saml_user_idp_initiated, login_saml_user_sp_initiated
    from flask import redirect, request, url_for, session
    from flask.ext.login import login_user

    @csrf.exempt
    @app.route("/saml/sso/<idp_name>", methods=['POST'])
    def idp_initiated(idp_name):
        acs_url_scheme = app.config.get('ACS_URL_SCHEME')
        metadata_url = app.config.get('METADATA_URL')
        user, saml_attributes = login_saml_user_idp_initiated(
            idp_name,
            acs_url_scheme,
            metadata_url,
            request.form['SAMLResponse'],
            db)

        session['saml_attributes'] = saml_attributes
        login_user(user)

        # NOTE:
        #   On a production system, the RelayState MUST be checked
        #   to make sure it doesn't contain dangerous URLs!
        if 'RelayState' in request.form:
            url = request.form['RelayState']
        # TODO : see what validation would need to be done to this value by
        #        adding the chiclet to Okta and testing

        # TODO : accept 'next' parameter, pass through to SAML, get back in the
        # post, validate it and redirect to it
        return redirect(saml.get_next_url(request))

    @csrf.exempt
    @app.route("/saml/login/<idp_name>")
    def sp_initiated(idp_name):
        acs_url_scheme = app.config.get('ACS_URL_SCHEME')
        metadata_url = app.config.get('METADATA_URL')
        redirect_url = login_saml_user_sp_initiated(idp_name,
                                                    acs_url_scheme,
                                                    metadata_url)
        response = redirect(redirect_url, code=302)
        # NOTE:
        #   I realize I _technically_ don't need to set Cache-Control or Pragma:
        #     http://stackoverflow.com/a/5494469
        #   However, Section 3.2.3.2 of the SAML spec suggests they are set:
        #     http://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf
        #   We set those headers here as a "belt and suspenders" approach,
        #   since enterprise environments don't always conform to RFCs
        response.headers['Cache-Control'] = 'no-cache, no-store'
        response.headers['Pragma'] = 'no-cache'
        return response

### Flask-Security ###
from flask.ext.security import Security, SQLAlchemyUserDatastore
user_datastore = SQLAlchemyUserDatastore(db, User, Role)
security = Security(app, user_datastore)


### Flask Mail ###
from flask_mail import Mail
mail = Mail(app=app)
from security_monkey.common.utils.utils import send_email as common_send_email


@security.send_mail_task
def send_email(msg):
    """
    Overrides the Flask-Security/Flask-Mail integration
    to send emails out via boto and ses.
    """
    common_send_email(subject=msg.subject, recipients=msg.recipients, html=msg.html)


### FLASK API ###
from flask.ext.restful import Api
api = Api(app)

from security_monkey.views.account import AccountGetPutDelete
from security_monkey.views.account import AccountPostList
api.add_resource(AccountGetPutDelete, '/api/1/accounts/<int:account_id>')
api.add_resource(AccountPostList, '/api/1/accounts')

from security_monkey.views.distinct import Distinct
api.add_resource(Distinct, '/api/1/distinct/<string:key_id>')

from security_monkey.views.ignore_list import IgnoreListGetPutDelete
from security_monkey.views.ignore_list import IgnorelistListPost
api.add_resource(IgnoreListGetPutDelete, '/api/1/ignorelistentries/<int:item_id>')
api.add_resource(IgnorelistListPost, '/api/1/ignorelistentries')

from security_monkey.views.item import ItemList
from security_monkey.views.item import ItemGet
api.add_resource(ItemList, '/api/1/items')
api.add_resource(ItemGet, '/api/1/items/<int:item_id>')

from security_monkey.views.item_comment import ItemCommentPost
from security_monkey.views.item_comment import ItemCommentDelete
from security_monkey.views.item_comment import ItemCommentGet
api.add_resource(ItemCommentPost, '/api/1/items/<int:item_id>/comments')
api.add_resource(ItemCommentDelete, '/api/1/items/<int:item_id>/comments/<int:comment_id>')
api.add_resource(ItemCommentGet, '/api/1/items/<int:item_id>/comments/<int:comment_id>')

from security_monkey.views.item_issue import ItemAuditGet
from security_monkey.views.item_issue import ItemAuditList
api.add_resource(ItemAuditList, '/api/1/issues')
api.add_resource(ItemAuditGet, '/api/1/issues/<int:audit_id>')

from security_monkey.views.item_issue_justification import JustifyPostDelete
api.add_resource(JustifyPostDelete, '/api/1/issues/<int:audit_id>/justification')

from security_monkey.views.logout import Logout
api.add_resource(Logout, '/api/1/logout')

from security_monkey.views.revision import RevisionList
from security_monkey.views.revision import RevisionGet
api.add_resource(RevisionList, '/api/1/revisions')
api.add_resource(RevisionGet, '/api/1/revisions/<int:revision_id>')

from security_monkey.views.revision_comment import RevisionCommentPost
from security_monkey.views.revision_comment import RevisionCommentGet
from security_monkey.views.revision_comment import RevisionCommentDelete
api.add_resource(RevisionCommentPost, '/api/1/revisions/<int:revision_id>/comments')
api.add_resource(RevisionCommentGet, '/api/1/revisions/<int:revision_id>/comments/<int:comment_id>')
api.add_resource(RevisionCommentDelete, '/api/1/revisions/<int:revision_id>/comments/<int:comment_id>')

from security_monkey.views.user_settings import UserSettings
api.add_resource(UserSettings, '/api/1/settings')

from security_monkey.views.whitelist import WhitelistGetPutDelete
from security_monkey.views.whitelist import WhitelistListPost
api.add_resource(WhitelistGetPutDelete, '/api/1/whitelistcidrs/<int:item_id>')
api.add_resource(WhitelistListPost, '/api/1/whitelistcidrs')

from security_monkey.views.auditor_settings import AuditorSettingsGet
from security_monkey.views.auditor_settings import AuditorSettingsPut
api.add_resource(AuditorSettingsGet, '/api/1/auditorsettings')
api.add_resource(AuditorSettingsPut, '/api/1/auditorsettings/<int:as_id>')
