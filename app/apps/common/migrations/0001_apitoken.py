from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="APIToken",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("name", models.CharField(max_length=255, verbose_name="Name")),
                (
                    "token_key",
                    models.CharField(
                        db_index=True,
                        max_length=16,
                        unique=True,
                        verbose_name="Token key",
                    ),
                ),
                ("token_hash", models.CharField(max_length=255, verbose_name="Token hash")),
                (
                    "last_used_at",
                    models.DateTimeField(
                        blank=True,
                        null=True,
                        verbose_name="Last used at",
                    ),
                ),
                (
                    "expires_at",
                    models.DateTimeField(blank=True, null=True, verbose_name="Expires at"),
                ),
                (
                    "revoked_at",
                    models.DateTimeField(blank=True, null=True, verbose_name="Revoked at"),
                ),
                (
                    "created_at",
                    models.DateTimeField(auto_now_add=True, verbose_name="Created at"),
                ),
                (
                    "updated_at",
                    models.DateTimeField(auto_now=True, verbose_name="Updated at"),
                ),
                (
                    "user",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="api_tokens",
                        to=settings.AUTH_USER_MODEL,
                        verbose_name="User",
                    ),
                ),
            ],
            options={
                "verbose_name": "API token",
                "verbose_name_plural": "API tokens",
                "ordering": ["-created_at"],
            },
        ),
        migrations.AddIndex(
            model_name="apitoken",
            index=models.Index(fields=["user", "revoked_at"], name="common_apit_user_id_7d6928_idx"),
        ),
        migrations.AddIndex(
            model_name="apitoken",
            index=models.Index(fields=["expires_at"], name="common_apit_expires_bd6178_idx"),
        ),
    ]
