from typing import Literal, Optional

import httpx

from .exceptions import APIException, HTTPException
from .types import KavenegarResponse


# Default requests timeout in seconds.
DEFAULT_TIMEOUT = 10


class AIOKavenegarAPI(object):
    def __init__(self, apikey, timeout=None):
        self.version = "v1"
        self.host = "api.kavenegar.com"
        self.apikey = apikey
        self.timeout = timeout or DEFAULT_TIMEOUT
        self.headers = {
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
            "charset": "utf-8",
        }

    def __repr__(self):
        return "kavenegar.AIOKavenegarAPI({!r})".format(self.apikey)

    def __str__(self):
        return "kavenegar.AIOKavenegarAPI({!s})".format(self.apikey)

    async def _request(
        self,
        action: Literal["sms", "verify", "call", "account"],
        method: str,
        params: Optional[dict] = None,
    ) -> dict:
        url = (
            f"https://{self.host}/{self.version}/{self.apikey}"
            f"/{action}/{method}.json"
        )

        try:
            async with httpx.AsyncClient() as client:
                http_response = await client.post(
                    url,
                    headers=self.headers,
                    data=params,
                    timeout=self.timeout,
                )

                try:
                    response: KavenegarResponse = http_response.json()

                    if response["return"]["status"] == 200:
                        return response["entries"]
                    else:
                        raise APIException(
                            "APIException[{}] {}".format(
                                response["return"]["status"],
                                response["return"]["message"],
                            )
                        )
                except ValueError as e:
                    raise HTTPException(e) from e

        except httpx.RequestError as e:
            raise HTTPException(e) from e

    async def sms_send(self, params: Optional[dict] = None) -> dict:
        return await self._request("sms", "send", params)

    async def sms_sendarray(self, params: Optional[dict] = None) -> dict:
        return await self._request("sms", "sendarray", params)

    async def sms_status(self, params: Optional[dict] = None) -> dict:
        return await self._request("sms", "status", params)

    async def sms_statuslocalmessageid(
        self, params: Optional[dict] = None
    ) -> dict:
        return await self._request("sms", "statuslocalmessageid", params)

    async def sms_select(self, params: Optional[dict] = None) -> dict:
        return await self._request("sms", "select", params)

    async def sms_selectoutbox(self, params: Optional[dict] = None) -> dict:
        return await self._request("sms", "selectoutbox", params)

    async def sms_latestoutbox(self, params: Optional[dict] = None) -> dict:
        return await self._request("sms", "latestoutbox", params)

    async def sms_countoutbox(self, params: Optional[dict] = None) -> dict:
        return await self._request("sms", "countoutbox", params)

    async def sms_cancel(self, params: Optional[dict] = None) -> dict:
        return await self._request("sms", "cancel", params)

    async def sms_receive(self, params: Optional[dict] = None) -> dict:
        return await self._request("sms", "receive", params)

    async def sms_countinbox(self, params: Optional[dict] = None) -> dict:
        return await self._request("sms", "countinbox", params)

    async def sms_countpostalcode(self, params: Optional[dict] = None) -> dict:
        return await self._request("sms", "countpostalcode", params)

    async def sms_sendbypostalcode(
        self, params: Optional[dict] = None
    ) -> dict:
        return await self._request("sms", "sendbypostalcode", params)

    async def verify_lookup(self, params: Optional[dict] = None) -> dict:
        return await self._request("verify", "lookup", params)

    async def call_maketts(self, params: Optional[dict] = None) -> dict:
        return await self._request("call", "maketts", params)

    async def call_status(self, params: Optional[dict] = None) -> dict:
        return await self._request("call", "status", params)

    async def account_info(self):
        return await self._request("account", "info")

    async def account_config(self, params: Optional[dict] = None) -> dict:
        return await self._request("account", "config", params)
