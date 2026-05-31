from django.contrib import admin
from django.utils.translation import gettext_lazy as _
from django.utils import timezone

from apps.common.models import APIToken


@admin.action(description=_("Make public"))
def make_public(modeladmin, request, queryset):
    queryset.update(visibility="public")


@admin.action(description=_("Make private"))
def make_private(modeladmin, request, queryset):
    queryset.update(visibility="private")


@admin.action(description=_("Revoke selected API tokens"))
def revoke_api_tokens(modeladmin, request, queryset):
    queryset.update(revoked_at=timezone.now())


class SharedObjectModelAdmin(admin.ModelAdmin):
    actions = [make_public, make_private]

    list_display = ("__str__", "visibility", "owner", "get_shared_with")

    @admin.display(description=_("Shared with users"))
    def get_shared_with(self, obj):
        return ", ".join([p.email for p in obj.shared_with.all()])

    def get_queryset(self, request):
        # Use the all_objects manager to show all transactions, including deleted ones
        return self.model.all_objects.all()


@admin.register(APIToken)
class APITokenAdmin(admin.ModelAdmin):
    actions = [revoke_api_tokens]
    list_display = (
        "name",
        "user",
        "token_key",
        "created_at",
        "last_used_at",
        "expires_at",
        "revoked_at",
    )
    search_fields = ("name", "user__email", "token_key")
    readonly_fields = (
        "user",
        "name",
        "token_key",
        "created_at",
        "updated_at",
        "last_used_at",
        "expires_at",
        "revoked_at",
    )

    def has_add_permission(self, request):
        return False
