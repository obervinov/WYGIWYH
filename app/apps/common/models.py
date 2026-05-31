import secrets

from django.contrib.auth.hashers import check_password, make_password
from django.db import models
from django.conf import settings
from django.db.models import Q
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from apps.common.middleware.thread_local import get_current_user


class SharedObjectManager(models.Manager):
    def get_queryset(self):
        """Return only objects the user can access"""
        user = get_current_user()
        base_qs = super().get_queryset()

        if user and user.is_authenticated:
            return base_qs.filter(
                Q(visibility="public")
                | Q(owner=user)
                | Q(shared_with=user)
                | Q(visibility="private", owner=None)
            ).distinct()

        return base_qs.filter(visibility="public")


class SharedObject(models.Model):
    # Access control enum
    class Visibility(models.TextChoices):
        private = "private", _("Private")
        is_paid = "public", _("Public")

    # Core sharing fields
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="%(class)s_owned",
        null=True,
        blank=True,
        verbose_name=_("Owner"),
    )
    visibility = models.CharField(
        max_length=10,
        choices=Visibility.choices,
        default=Visibility.private,
        verbose_name=_("Visibility"),
    )
    shared_with = models.ManyToManyField(
        settings.AUTH_USER_MODEL,
        related_name="%(class)s_shared",
        blank=True,
        verbose_name=_("Shared with users"),
    )

    # Use as abstract base class
    class Meta:
        abstract = True
        indexes = [
            models.Index(fields=["visibility"]),
        ]

    def is_accessible_by(self, user):
        """Check if a user can access this object"""
        return (
            self.visibility == "public"
            or self.owner == user
            or (self.visibility == "shared" and user in self.shared_with.all())
        )

    def save(self, *args, **kwargs):
        if not self.pk and not self.owner:
            self.owner = get_current_user()
        super().save(*args, **kwargs)


class OwnedObjectManager(models.Manager):
    def get_queryset(self):
        """Return only objects the user can access"""
        user = get_current_user()
        base_qs = super().get_queryset()

        if user and user.is_authenticated:
            return base_qs.filter(Q(owner=user) | Q(owner=None)).distinct()

        return base_qs


class OwnedObject(models.Model):
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="%(class)s_owned",
        null=True,
        blank=True,
    )

    # Use as abstract base class
    class Meta:
        abstract = True

    def save(self, *args, **kwargs):
        if not self.pk and not self.owner:
            self.owner = get_current_user()
        super().save(*args, **kwargs)


class APITokenManager(models.Manager):
    def create_token(self, *, user, name: str, expires_at=None):
        token_key = self.model.generate_token_key()
        token_secret = secrets.token_urlsafe(32)
        token = self.model(
            user=user,
            name=name,
            token_key=token_key,
            token_hash=make_password(token_secret),
            expires_at=expires_at,
        )
        token.full_clean()
        token.save()
        return token, token.build_raw_token(token_secret)


class APIToken(models.Model):
    TOKEN_PREFIX = "wygiwyh_pat_"

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="api_tokens",
        verbose_name=_("User"),
    )
    name = models.CharField(max_length=255, verbose_name=_("Name"))
    token_key = models.CharField(
        max_length=16,
        unique=True,
        db_index=True,
        verbose_name=_("Token key"),
    )
    token_hash = models.CharField(max_length=255, verbose_name=_("Token hash"))
    last_used_at = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name=_("Last used at"),
    )
    expires_at = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name=_("Expires at"),
    )
    revoked_at = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name=_("Revoked at"),
    )
    created_at = models.DateTimeField(auto_now_add=True, verbose_name=_("Created at"))
    updated_at = models.DateTimeField(auto_now=True, verbose_name=_("Updated at"))

    objects = APITokenManager()

    class Meta:
        indexes = [
            models.Index(fields=["user", "revoked_at"]),
            models.Index(fields=["expires_at"]),
        ]
        ordering = ["-created_at"]
        verbose_name = _("API token")
        verbose_name_plural = _("API tokens")

    def __str__(self):
        return f"{self.user} / {self.name}"

    @classmethod
    def generate_token_key(cls) -> str:
        while True:
            candidate = secrets.token_hex(8)
            if not cls.objects.filter(token_key=candidate).exists():
                return candidate

    @classmethod
    def parse_raw_token(cls, raw_token: str):
        if not raw_token.startswith(cls.TOKEN_PREFIX):
            raise ValueError("Token is missing the expected prefix.")

        payload = raw_token.removeprefix(cls.TOKEN_PREFIX)
        token_key, separator, token_secret = payload.partition(".")
        if not separator or not token_key or not token_secret:
            raise ValueError("Token is malformed.")
        return token_key, token_secret

    def build_raw_token(self, token_secret: str) -> str:
        return f"{self.TOKEN_PREFIX}{self.token_key}.{token_secret}"

    def check_secret(self, raw_secret: str) -> bool:
        return check_password(raw_secret, self.token_hash)

    def is_expired(self) -> bool:
        return self.expires_at is not None and self.expires_at <= timezone.now()
