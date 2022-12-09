# Project module imports
from CTFd.plugins import register_plugin_assets_directory, override_template
from CTFd.utils.decorators import ratelimit
from CTFd.models import Users, db
from CTFd.utils.security.auth import login_user
from CTFd.utils.decorators import authed_only
from CTFd.utils.user import get_current_user

# External module imports
from flask import request, session, Blueprint, redirect
from flask_restx import Api

import os
import logging
import json

# Local module imports
from .discord_oauth import Discord_Oauth
from .discord_database import DiscordUser
from .discord_api import discord_namespace
# Global variables
# Used primarily due to flask routed functions being unable to use class "self" reflections
plugin_name = "Discord_Oauth"
log = logging.getLogger(plugin_name)
discord_oauth = None
discord_blueprint = Blueprint("discord_oauth", __name__, template_folder="assets")


def override_page(base_asset_path: str, page: str):
    """
    Overrides login page with custom login page with Discord Login button.

    :base_asset_path: Path to the plugin assets directory on the filesystem
    :page: Page to overwrite from the templates to actual
    :return: None
    """
    template_path = os.path.join(base_asset_path, page)
    try:
        override_template(page, open(template_path).read())
    except OSError:
        log.error("Unable to replace {} template".format(page))

# Routes


@discord_blueprint.route("/discord/oauth", methods=["GET"])
@ratelimit(method="GET", limit=10, interval=10)
@authed_only
def discord_oauth_login():
    """
    Configures Discord Oauth and redirects to Discord Login

    :return: Redirect to Discord's OAuth2 login page
    """
    global discord_oauth
    user = get_current_user()

    log.debug("Session: [{}]".format(session))
    log.debug("OAuth: [{}]".format(str(discord_oauth)))
    print(f'Received {user.id}')
    # Passing user_id over state is pretty sus
    return redirect(discord_oauth.gen_auth_url())


@discord_blueprint.route("/discord/oauth_callback", methods=["GET", "POST"])
@ratelimit(method="POST", limit=10, interval=5)
@authed_only
def discord_oauth_callback():
    """
    Callback response configured to come from Discord's OAuth2 redirect

    :return: Redirect to users login home page (or error)
    """
    log.debug("Request: [{}]".format(request))
    log.debug("Session: [{}]".format(session))
    log.debug("OAuth Response Code: [{}]".format(request.args.get("code")))
    global discord_oauth
    token = discord_oauth.get_access_token(request.args.get("code"))
    user = get_current_user()

    log.debug("token=[{}]".format(token))
    user_json = discord_oauth.get_user_info(token)
    log.debug("User data: [{}]".format(str(user_json)))
    # process user info/login/etc
    if user_json:
        # lookup by email
        discord_user = DiscordUser.query.filter_by(id=user.id).first()
        if user is None:
            # User doesn't exist, this shouldn't happen
            log.error("Login failed: user[{user}], discord_user[{d_user}], \
                oauth[{user_json}]".format(user=user, d_user=discord_user,
                                           user_json=user_json))
            return "Error connecting account via Discord Oauth2 - user ID doesn't exist"

        else:
            # Create Discord association if does not exist (legacy support)
            if not discord_user:
                discord_user = DiscordUser(
                    id=user.id,
                    discord_id=user_json["id"],
                    username=user_json["username"],
                    discriminator=user_json["discriminator"],
                    avatar_hash=user_json["avatar"],
                    mfa_enabled=user_json["mfa_enabled"],
                    verified=user_json["verified"],
                    email=user_json["email"]
                )
                # Connect CTFd -> discord
                user.oauth_id = user.id  # This marks that the discord association was created
                # Connect discord -> CTFd
                db.session.add(discord_user)
                db.session.add(user)
                db.session.commit()
            else:
                log.error("Login failed: user[{user}], discord_user[{d_user}], \
                oauth[{user_json}]".format(user=user, d_user=discord_user,
                                           user_json=user_json))
                # TODO allow people to change discord association
                return "Error connecting account via Discord Oauth2 - discord association already created"
    else:
        return "Error logging in via Discord OAuth2"
    return redirect('/user')


def check_debug_mode(debug: bool):
    """
    Checks for DEBUG mode and activates logger accordingly

    :debug: Variable to toggle debug or info
    """
    if debug:
        logging.basicConfig(level=logging.DEBUG)
        log.debug("Debug mode enabled.")
    else:
        logging.basicConfig(level=logging.INFO)
        log.info("Log level {} enabled.".format(logging.getLevelName(log.getEffectiveLevel())))


def load_config():
    """
    Loads plugin configuration file from disk

    :return: JSON object with config contents, or None if errored
    """
    conf_location = os.path.dirname(os.path.realpath(__file__)) + "/../config.json"

    try:
        with open(conf_location, "r") as conf_file:
            return json.load(conf_file)
    # EnvironmentError is wraps IOError, OSError, and WindowsError
    except EnvironmentError:
        log.error("Unable to load config file: [{}]".format(conf_location))
        return None


def string_to_bool(string: str):
    """
    :string: String to parse as boolean
    :return: True if string is "true" (case insensitive), false otherwise
    """
    if string.lower() == "true":
        return True
    else:
        return False


def setup_oauth(config):
    """
    Sets up the global variable "discord_oauth"
    """
    global discord_oauth
    global plugin_name
    discord_oauth = Discord_Oauth(
        client_id=config["client_id"],
        client_secret=config["client_secret"],
        scope=config["scope"],
        redirect_uri="{}/discord/oauth_callback".format(config["domain"]),
        discord_api_url=config["base_discord_api_url"],
        plugin_name=plugin_name
    )

def generate_discord_url(oauth_id):
    discord_user = DiscordUser.query.filter_by(id=oauth_id).first()
    if discord_user:
        return "https://discordapp.com/users/{}".format(discord_user.discord_id)
    else:
        return ""

def generate_discord_name(oauth_id):
    discord_user = DiscordUser.query.filter_by(id=oauth_id).first()
    if discord_user:
        return "{}#{}".format(discord_user.username, discord_user.discriminator)
    else:
        return ""

# Load plugin into CTFd
def load(app):
    """
    Hook for CTFd to load the plugin

    :app: CTFd flask insert
    :return: None
    """
    # Basic Setup
    config = load_config()
    check_debug_mode(string_to_bool(config["debug"]))
    log.debug("Loaded config: [{}]".format(config))

    # OAuth setup
    setup_oauth(config)

    # Get plugin asset path
    base_asset_path = os.path.dirname(os.path.realpath(__file__)) + "/../assets/"
    register_plugin_assets_directory(app, base_path=base_asset_path)

    # DB Setup
    app.db.create_all()

    # Registration
    override_page(base_asset_path, "users/private.html")
    override_page(base_asset_path, "scoreboard.html")
    app.register_blueprint(discord_blueprint)
    log.info("Discord OAuth2 URL -> https://{}/discord/oauth_callback".format(config["domain"]))

    # API Routes
    api_blueprint = Blueprint("discord_api", __name__)
    discord_api = Api(api_blueprint, version="v1", doc=app.config.get("SWAGGER_UI"))
    discord_api.add_namespace(discord_namespace, "/discord")
    app.register_blueprint(api_blueprint, url_prefix="/api/v1")

    # Jinja functions
    app.jinja_env.globals.update(generate_discord_url=generate_discord_url)
    app.jinja_env.globals.update(generate_discord_name=generate_discord_name)