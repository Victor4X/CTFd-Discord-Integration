from flask_restx import Namespace, Resource
from flask import session, jsonify
from CTFd.models import db

from .discord_database import DiscordUser
from CTFd.utils.decorators import authed_only
from CTFd.utils.user import get_current_user
from CTFd.utils.decorators import ratelimit
from flask import request, session, Blueprint, redirect

from CTFd.utils.decorators.visibility import (
    check_challenge_visibility,
    check_score_visibility,
    check_account_visibility
)
from CTFd.utils.config.visibility import (
    scores_visible,
    accounts_visible,
    challenges_visible,
)
from sqlalchemy.sql import or_, and_, any_

discord_namespace = Namespace('discord', description="Endpoint to retrieve users by discord ID")

# /api/v1/discord/delete
@discord_namespace.route("/delete", methods=["GET"])
class DiscordUserAPIDelete(Resource):

    @authed_only
    @discord_namespace.doc(
        description="Endpoint to get a delete DiscordUser object + Association",
        responses={
            200: ("Success", "UserDetailedSuccessResponse"),
            400: (
                "An error occured processing the provided or stored data",
                "APISimpleErrorResponse",
            ),
        },
    )
    def get(self):
        """
        Deletes Discord Association

        :return: Redirect to Profile Page
        """
        user = get_current_user()
        user.oauth_id = 0

        discord_user = DiscordUser.query.filter_by(id=user.id).first()

        db.session.add(user)
        db.session.delete(discord_user)
        db.session.commit()
        print("Successfully deleted discord association")
        return redirect("/user")


@discord_namespace.route("/<id>")
@discord_namespace.param("id", "Discord User ID")
class DiscordUserAPI(Resource):
    @check_account_visibility
    @discord_namespace.doc(
        description="Endpoint to get a specific DiscordUser object",
        responses={
            200: ("Success", "UserDetailedSuccessResponse"),
            400: (
                "An error occured processing the provided or stored data",
                "APISimpleErrorResponse",
            ),
        },
    )
    def get(self, id):
        user = DiscordUser.query.filter_by(discord_id=id).first_or_404()
        response = {}

        response["id"] = user.id

        return {"success": True, "data": response}
