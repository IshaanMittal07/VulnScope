"""Target intake: register a service to assess."""

from fastapi import APIRouter, status

from app.api.deps import DbSession
from app.models import Target
from app.schemas import TargetCreate, TargetRead

router = APIRouter(prefix="/targets", tags=["targets"])


@router.post("", status_code=status.HTTP_201_CREATED)
def create_target(body: TargetCreate, db: DbSession) -> TargetRead:
    target = Target(**body.model_dump())
    db.add(target)
    db.commit()
    return TargetRead.model_validate(target)
