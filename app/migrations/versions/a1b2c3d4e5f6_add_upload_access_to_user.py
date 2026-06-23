"""Add upload_access to user table

Revision ID: a1b2c3d4e5f6
Revises: 78c33e9bffce
Branch Labels: None
depends_on: None

"""
from alembic import op
import sqlalchemy as sa

revision = 'a1b2c3d4e5f6'
down_revision = '78c33e9bffce'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('user') as batch_op:
        batch_op.add_column(sa.Column('upload_access', sa.Boolean(), nullable=True, server_default='0'))


def downgrade():
    with op.batch_alter_table('user') as batch_op:
        batch_op.drop_column('upload_access')
