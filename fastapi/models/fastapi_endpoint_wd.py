# Copyright 2022 ACSONE SA/NV
# License LGPL-3.0 or later (http://www.gnu.org/licenses/LGPL).
import logging
from enum import Enum
from typing import List
import odoo
from odoo import _, api, fields, models
from odoo.api import Environment
from odoo.modules.registry import Registry
from odoo.exceptions import AccessError, MissingError, UserError, ValidationError
from odoo.addons.base.models.res_partner import Partner
from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request, Response, status

from pydantic import BaseModel, Field
from fastapi.security import APIKeyHeader


_logger = logging.getLogger(__name__)

from ..depends import (
    authenticated_partner,
    authenticated_partner_from_basic_auth_user,
    authenticated_partner_impl,
    fastapi_endpoint,
    odoo_env,
)


class FastapiEndpointWD(models.Model):

    _inherit = "fastapi.endpoint"

    app: str = fields.Selection(selection_add=[('wd', 'Warp Driven Endpoint')], ondelete={"wd": "cascade"})
    wd_auth_method = fields.Selection(
        selection=[("api_key", "Api Key"), ("http_basic", "HTTP Basic")],
        string="Authenciation method",
    )

    def _get_fastapi_routers(self):
        if self.app == "wd":
            return [wd_api_router]
        return super()._get_fastapi_routers()


    @api.constrains("app", "wd_auth_method")
    def _valdiate_wd_auth_method(self):
        for rec in self:
            if rec.app == "wd" and not rec.wd_auth_method:
                raise ValidationError(
                    _(
                        "The authentication method is required for app %(app)s",
                        app=rec.app,
                    )
                )

    @api.model
    def _fastapi_app_fields(self) -> List[str]:
        fields = super()._fastapi_app_fields()
        fields.append("wd_auth_method")
        return fields

    def _get_app(self):
        app = super()._get_app()
        if self.app == "wd":
            # Here we add the overrides to the authenticated_partner_impl method
            # according to the authentication method configured on the demo app
            if self.wd_auth_method == "http_basic":
                authenticated_partner_impl_override = (
                    authenticated_partner_from_basic_auth_user
                )
            else:
                authenticated_partner_impl_override = (
                    api_key_based_authenticated_partner_impl
                )
            app.dependency_overrides[
                authenticated_partner_impl
            ] = authenticated_partner_impl_override
        return app



class UserInfo(BaseModel):
    name: str
    display_name: str


class EndpointAppInfo(BaseModel):
    id: str
    name: str
    app: str
    auth_method: str = Field(alias="wd_auth_method")
    root_path: str

    class Config:
        orm_mode = True

wd_api_router = APIRouter()

@wd_api_router.get("/")
async def hello_word():
    """Hello World!"""
    return {"Hello": "World WD"}


class ResultInfo(BaseModel):
    code: str
    error: str
    message: str


@wd_api_router.post("/signup")
async def signup(login, name, password, lang='en_US', env=Depends(odoo_env)):
    use_obj = env['res.users']
    use_sudo_obj = use_obj.sudo()

    res = use_sudo_obj.sudo().signup({
        'login': login,
        'name': name,
        'password': password,
        'lang': lang,
    })

    new_user = use_sudo_obj.search(
        use_obj._get_login_domain(login), order=use_obj._get_login_order(), limit=1
    )

    if new_user:
        return ResultInfo(code='0', error='0', message='signup user ok')
    else:
        return ResultInfo(code='99', error='99', message='signup user fail')





@wd_api_router.post("/login")
async def login(login=None, password=None, env=Depends(odoo_env)):
    use_obj = env['res.users']
    use_sudo_obj = use_obj.sudo()

    # wsgienv = {
    #     'interactive': True,
    #     'base_location': request.httprequest.url_root.rstrip('/'),
    #     'HTTP_HOST': request.httprequest.environ['HTTP_HOST'],
    #     'REMOTE_ADDR': request.httprequest.environ['REMOTE_ADDR'],
    # }
    #registry = Registry(dbname)
    #pre_uid = registry['res.users'].authenticate(env.cr.dbname, login, password, wsgienv)

    _logger.info('====fastapi.wd.login=======%s %s' % (login, password))

    try:
        uid = use_obj._login(env.cr.dbname, login, password, user_agent_env=False)
        _logger.info('====fastapi.wd.login=2======%s' % (uid))
        return ResultInfo(code='0', error='0',  message='uid:%s login ok' % uid)
    except Exception as e:
        _logger.info('====fastapi.wd.login fail=======%s' % (e))
        return ResultInfo(code='99', error='99', message=str(e))



@wd_api_router.post("/reset_password")
async def rest_passowrd(login, lang='en_US', env=Depends(odoo_env)):
    use_obj = env['res.users']
    use_sudo_obj = use_obj.sudo()
    try:
        # res = use_sudo_obj.browse(uid).change_password(old_password, new_password)
        res = use_sudo_obj.sudo().reset_password(login)
        _logger.info('====fastapi.wd.reset_password  fail=======%s' % (res))
        message = 'Password reset instructions sent to your email'
        return ResultInfo(code='0', error='0', message=message)
    except Exception as e:
        _logger.info('====fastapi.wd.reset_password  fail=======%s' % (e))
        return ResultInfo(code='99', error='99', message=str(e))




class PartnerInfo(BaseModel):
    name: str
    email: str

@wd_api_router.get("/partners", response_model=list[PartnerInfo])
def get_partners(env=Depends(odoo_env)) -> list[PartnerInfo]:
    return [
        PartnerInfo(name=partner.name, email=partner.email)
        for partner in env["res.partner"].search([])]


class ExceptionType(str, Enum):
    user_error = "UserError"
    validation_error = "ValidationError"
    access_error = "AccessError"
    missing_error = "MissingError"
    http_exception = "HTTPException"
    bare_exception = "BareException"



@wd_api_router.get("/exception")
async def exception(exception_type: ExceptionType, error_message: str):
    exception_classes = {
        ExceptionType.user_error: UserError,
        ExceptionType.validation_error: ValidationError,
        ExceptionType.access_error: AccessError,
        ExceptionType.missing_error: MissingError,
        ExceptionType.http_exception: HTTPException,
        ExceptionType.bare_exception: NotImplementedError,  # any exception child of Exception
    }
    exception_cls = exception_classes[exception_type]
    if exception_cls is HTTPException:
        raise exception_cls(status_code=status.HTTP_409_CONFLICT, detail=error_message)
    raise exception_classes[exception_type](error_message)

@wd_api_router.get(
    "/endpoint_app_info",
    response_model=EndpointAppInfo,
    dependencies=[Depends(authenticated_partner)],
)
async def endpoint_app_info(
    endpoint: FastapiEndpointWD = Depends(fastapi_endpoint),  # noqa: B008
) -> EndpointAppInfo:
    """Returns the current endpoint configuration"""
    # This method show you how to get access to current endpoint configuration
    # It also show you how you can specify a dependency to force the security
    # even if the method doesn't require the authenticated partner as parameter
    return EndpointAppInfo.from_orm(endpoint)

def api_key_based_authenticated_partner_impl(
    api_key: str = Depends(  # noqa: B008
        APIKeyHeader(
            name="api-key",
            description="In this demo, you can use a user's login as api key.",
        )
    ),
    env: Environment = Depends(odoo_env),  # noqa: B008
) -> Partner:
    """A dummy implementation that look for a user with the same login
    as the provided api key
    """
    _logger.info(f'api_key: {api_key}')
    partner = (
        env["res.users"].sudo().search([("login", "=", api_key)], limit=1).partner_id
    )
    if not partner:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect API Key"
        )
    return partner
