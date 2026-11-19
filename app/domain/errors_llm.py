from app.domain.errors import DomainError


class LlmUnavailableError(DomainError):
    code = "llm_unavailable"
    default_message = "El servicio de modelo de lenguaje no está disponible."
