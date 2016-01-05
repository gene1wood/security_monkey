import requests
from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT, entity
from saml2.client import Saml2Client
from saml2.config import Config as Saml2Config
import flask
from security_monkey.datastore import User

from urlparse import urlparse, urljoin
import logging


def get_next_url(request):
    host = urlparse(request.host_url).netloc
    path = request.args.get('next') if 'next' in request.args else '/'

    # This is unforgivably ugly but I can't for the life of me figure out
    # how to work around Flask's `request` object having the wrong scheme
    # when Flask sits behind a reverse nginx proxy
    redirect_url = 'https://%s%s' % (host, path)
    return redirect_url
#     redirect_url = urljoin(request.host_url, request.args.get('next'))
#     ref_url = urlparse(request.host_url)
#     test_url = urlparse(redirect_url)
#     if (test_url.scheme in ('http', 'https')
#             and ref_url.netloc == test_url.netloc):
#         return redirect_url
#     else:
#         return request.host_url


def get_saml_client(idp_name,
                    acs_url_scheme,
                    metadata_url):
    acs_url = flask.url_for(
        "idp_initiated",
        idp_name=idp_name,
        _external=True,
        _scheme=acs_url_scheme)

    rv = requests.get(metadata_url)

    # NOTE:
    #   Ideally, this should fetch the metadata and pass it to
    #   PySAML2 via the "inline" metadata type.
    #   However, this method doesn't seem to work on PySAML2 v2.4.0
    #
    #   SAML metadata changes very rarely. On a production system,
    #   this data should be cached as appropriate for your production system.
    import tempfile
    tmp = tempfile.NamedTemporaryFile()
    f = open(tmp.name, 'w')
    f.write(rv.text)
    f.close()

    settings = {
        'metadata': {
            # 'inline': metadata,
            "local": [tmp.name]
        },
        'service': {
            'sp': {
                'endpoints': {
                    'assertion_consumer_service': [
                        (acs_url, BINDING_HTTP_REDIRECT),
                        (acs_url, BINDING_HTTP_POST)
                    ],
                },
                # Don't verify that the incoming requests originate from us via
                # the built-in cache for authn request ids in pysaml2
                'allow_unsolicited': True,
                # Don't sign authn requests, since signed requests only make
                # sense in a situation where you control both the SP and IdP
                'authn_requests_signed': False,
                'logout_requests_signed': True,
                'want_assertions_signed': True,
                'want_response_signed': False,
            },
        },
    }
    spConfig = Saml2Config()
    spConfig.load(settings)
    spConfig.allow_unknown_attributes = True
    saml_client = Saml2Client(config=spConfig)
    tmp.close()
    return saml_client


def login_saml_user_idp_initiated(idp_name,
                                  acs_url_scheme,
                                  metadata_url,
                                  saml_response,
                                  db):
    saml_client = get_saml_client(idp_name,
                                  acs_url_scheme,
                                  metadata_url)

    authn_response = saml_client.parse_authn_request_response(
        saml_response,
        entity.BINDING_HTTP_POST)
    authn_response.get_identity()
    user_info = authn_response.get_subject()
    email = user_info.text
    saml_attributes = authn_response.ava

    # This is what as known as "Just In Time (JIT) provisioning".
    # What that means is that, if a user in a SAML assertion
    # isn't in the user store, we create that user first, then log them in
    user = User.query.filter(User.email == email).first()

    if not user:
        user = User(email=email, active=True)
        db.session.add(user)
        db.session.commit()
        db.session.close()
        user = User.query.filter(User.email == email).first()

    return user, saml_attributes


def login_saml_user_sp_initiated(idp_name,
                                 acs_url_scheme,
                                 metadata_url):
    saml_client = get_saml_client(idp_name,
                                  acs_url_scheme,
                                  metadata_url)
    reqid, info = saml_client.prepare_for_authenticate()

    redirect_url = None
    # Select the IdP URL to send the AuthN request to
    for key, value in info['headers']:
        if key is 'Location':
            redirect_url = value

    return redirect_url
