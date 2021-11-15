from CTFd.models import db


class DiscordUser(db.Model):
    __tablename__ = "discorduser"
    __table_args__ = (db.UniqueConstraint("id"), {})

    # Core variables
    id = db.Column(db.Integer, db.ForeignKey(
        "users.id", ondelete="CASCADE"), primary_key=True, unique=True)
    # Discord Username 2-32 characters
    username = db.Column(db.String(128))
    discord_id = db.Column(db.BigInteger)  # Discord ID, int64
    discriminator = db.Column(db.Integer)  # Discriminator ID, 4 digits
    avatar_hash = db.Column(db.String(256))  # Avatar hash, no known limit, 33 from samples
    mfa_enabled = db.Column(db.Boolean)
    verified = db.Column(db.Boolean)
    email = db.Column(db.String(256))

    def __init__(self, **kwargs):
        super(DiscordUser, self).__init__(**kwargs)
