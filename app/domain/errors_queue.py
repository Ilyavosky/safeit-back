from app.domain.errors import DomainError


class QueueUnavailableError(DomainError):
    code = "queue_unavailable"
    default_message = "La cola de trabajos no está disponible. Inténtalo de nuevo en unos minutos."
