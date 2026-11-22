class DomainError(Exception):
    code = "domain_error"
    default_message = "Ocurrió un error."

    def __init__(self, message: str | None = None) -> None:
        self.message = message or self.default_message
        super().__init__(self.message)


class EntityNotFoundError(DomainError):
    code = "not_found"
    default_message = "No se encontró el recurso solicitado."

    def __init__(self, entity: str, identifier: object | None = None) -> None:
        self.entity = entity
        self.identifier = identifier
        super().__init__()


class ConflictError(DomainError):
    code = "conflict"
    default_message = "El recurso ya existe o entra en conflicto con otro."


class InvalidCredentialsError(DomainError):
    code = "invalid_credentials"
    default_message = "Correo o contraseña incorrectos."


class MfaRequiredError(DomainError):
    code = "mfa_required"
    default_message = "Se requiere el código de verificación en dos pasos."


class InvalidMfaCodeError(DomainError):
    code = "invalid_mfa_code"
    default_message = "El código de verificación es incorrecto o expiró."


class InvalidTokenError(DomainError):
    code = "invalid_token"
    default_message = "La sesión no es válida o expiró."


class TokenReuseDetectedError(DomainError):
    code = "token_reuse_detected"
    default_message = "Se detectó un uso indebido de la sesión. Inicia sesión de nuevo."

    def __init__(self, family_id: object | None = None) -> None:
        self.family_id = family_id
        super().__init__()


class InvalidResetTokenError(DomainError):
    code = "invalid_reset_token"
    default_message = "El enlace para restablecer la contraseña no es válido o ya venció."


class MailDeliveryError(DomainError):
    code = "mail_delivery_failed"
    default_message = "No se pudo enviar el correo."


class PermissionDeniedError(DomainError):
    code = "permission_denied"
    default_message = "No tienes permiso para realizar esta acción."


class DomainAlreadyClaimedError(ConflictError):
    code = "domain_already_claimed"
    default_message = "Este dominio ya fue verificado por otra cuenta."


class InvalidCveIdError(DomainError):
    code = "invalid_cve_id"
    default_message = "El identificador de CVE no es válido. Usa el formato CVE-2024-12345."


class FeedUnavailableError(DomainError):
    code = "feed_unavailable"
    default_message = "No se pudo consultar la fuente de datos de vulnerabilidades."


class InvalidDomainNameError(DomainError):
    code = "invalid_domain_name"
    default_message = "El nombre de dominio no es válido. Usa el formato ejemplo.com."


class DomainNotVerifiedError(DomainError):
    code = "domain_not_verified"
    default_message = "El dominio debe verificarse antes de ejecutar escaneos o pruebas."


class DomainVerificationFailedError(DomainError):
    code = "domain_verification_failed"
    default_message = "No se pudo comprobar la propiedad del dominio."


class OutOfScopeError(DomainError):
    code = "out_of_scope"
    default_message = "El objetivo está fuera del alcance autorizado."


class EndpointNotWhitelistedError(OutOfScopeError):
    code = "endpoint_not_whitelisted"
    default_message = "El endpoint no está en la lista blanca de pruebas."


class ToolNotAllowedError(DomainError):
    code = "tool_not_allowed"
    default_message = "La herramienta no está en la lista cerrada de herramientas permitidas."

    def __init__(self, tool: str | None = None) -> None:
        self.tool = tool
        super().__init__()


class LlmOutputRejectedError(DomainError):
    code = "llm_output_rejected"
    default_message = "La salida del modelo no pasó la validación y fue descartada."


class WeakPasswordError(DomainError):
    code = "weak_password"
    default_message = "La contraseña no cumple los requisitos mínimos."


class RateLimitExceededError(DomainError):
    code = "rate_limited"
    default_message = "Demasiados intentos. Espera un momento e inténtalo de nuevo."


class InvalidStatusTransitionError(ConflictError):
    code = "invalid_status_transition"
    default_message = "La transición de estado solicitada no es válida."


class InvalidCursorError(DomainError):
    code = "invalid_cursor"
    default_message = "El cursor de paginación no es válido."


class PublicTargetNotAllowedError(DomainError):
    code = "public_target_not_allowed"
    default_message = "Este dominio no puede analizarse con el análisis público."


class NoticeNotAcceptedError(DomainError):
    code = "notice_not_accepted"
    default_message = "Debes aceptar el aviso de uso del análisis público."
