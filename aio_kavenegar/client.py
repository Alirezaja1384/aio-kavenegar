import json

from typing import Literal

import httpx

from aio_kavenegar.exceptions import APIException, HTTPException
from aio_kavenegar.types import KavenegarResponse


# Default requests timeout in seconds.
DEFAULT_TIMEOUT: int = 10
DEFAULT_HOST: str = "api.kavenegar.com"
DEFAULT_HEADERS: dict = {
    "Accept": "application/json",
    "Content-Type": "application/x-www-form-urlencoded",
    "charset": "utf-8",
}


class AIOKavenegarAPI:
    """
    https://kavenegar.com/rest.html
    """

    def __init__(
        self,
        apikey: str,
        timeout: int = DEFAULT_TIMEOUT,
        host: str = DEFAULT_HOST,
        headers: dict = DEFAULT_HEADERS,
        proxies: dict | None = None,
    ) -> None:
        """
        :param str apikey: Kavengera API Key
        :param int timeout: request timeout, default is 10
        :param str host: Kavenegar API host, default is `api.kavenegar.com`
        :param dict headers: headers used when requesting Kavenegar resources, default:
            {
                "Accept": "application/json",
                "Content-Type": "application/x-www-form-urlencoded",
                "charset": "utf-8",
            }
        :param dict proxies: Dictionary mapping protocol to the URL of the proxy:
            {
                'http': 'http://192.168.1.10:3128',
                'https': 'http://192.168.1.10:3129',
            }
        """
        self.version: str = "v1"
        self.host: str = host
        self.apikey: str = apikey
        self.apikey_mask: str = f"{apikey[:2]}********{apikey[-2:]}"
        self.timeout: int = timeout
        self.headers: dict = headers
        if not proxies:
            self.mounts: dict = None
        else:
            self.mounts: dict = {}
            if http := proxies.get("http"):
                self.mounts.update({"http://": httpx.HTTPTransport(proxy=http)})
            if https := proxies.get("https"):
                self.mounts.update({"https://": httpx.HTTPTransport(proxy=https)})

    def __repr__(self) -> str:
        return "kavenegar.AIOKavenegarAPI({!r})".format(self.apikey_mask)

    def __str__(self) -> str:
        return "kavenegar.AIOKavenegarAPI({!s})".format(self.apikey_mask)

    def _pars_params_to_json(self, params: dict) -> dict:
        """
        Kavenegar bug, the api server expects the parameters in a JSON-like array format,
        but the requests library form-encode each key-value pair

        Params (dict):
        { sender: ["30002626", "30002627", "30002727", ], }

        request behavior:
        sender=30002626&sender=30002627&sender=30002727

        Server expectation:
        sender=["30002626","30002627","30002727"]
        """
        # Convert lists to JSON-like strings
        formatted_params = {}
        for key, value in params.items():
            if isinstance(value, (dict, list, tuple)):
                formatted_params[key] = json.dumps(value)
            else:
                formatted_params[key] = value
        return formatted_params

    async def _request(
        self,
        action: Literal["sms", "verify", "call", "account"],
        method: str,
        params: dict = {},
    ) -> dict:
        params: dict = self._pars_params_to_json(params)
        url = f"https://{self.host}/{self.version}/{self.apikey}/{action}/{method}.json"

        try:
            async with httpx.AsyncClient(mounts=self.mounts) as client:
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
                            f"APIException[{response["return"]["status"]}] {response["return"]["message"]}"
                        )
                except ValueError as e:
                    raise HTTPException(e) from e

        except httpx.RequestError as e:
            message = str(e).replace(self.apikey, self.apikey_mask)
            raise HTTPException(message) from None

    async def sms_send(self, params: dict = {}) -> KavenegarResponse:
        return await self._request("sms", "send", params)

    async def sms_sendarray(self, params: dict = {}) -> KavenegarResponse:
        return await self._request("sms", "sendarray", params)

    async def sms_status(self, params: dict = {}) -> KavenegarResponse:
        return await self._request("sms", "status", params)

    async def sms_statuslocalmessageid(self, params: dict = {}) -> KavenegarResponse:
        return await self._request("sms", "statuslocalmessageid", params)

    async def sms_select(self, params: dict = {}) -> KavenegarResponse:
        return await self._request("sms", "select", params)

    async def sms_selectoutbox(self, params: dict = {}) -> KavenegarResponse:
        return await self._request("sms", "selectoutbox", params)

    async def sms_latestoutbox(self, params: dict = {}) -> KavenegarResponse:
        return await self._request("sms", "latestoutbox", params)

    async def sms_countoutbox(self, params: dict = {}) -> KavenegarResponse:
        return await self._request("sms", "countoutbox", params)

    async def sms_cancel(self, params: dict = {}) -> KavenegarResponse:
        return await self._request("sms", "cancel", params)

    async def sms_receive(self, params: dict = {}) -> KavenegarResponse:
        return await self._request("sms", "receive", params)

    async def sms_countinbox(self, params: dict = {}) -> KavenegarResponse:
        return await self._request("sms", "countinbox", params)

    async def sms_countpostalcode(self, params: dict = {}) -> KavenegarResponse:
        return await self._request("sms", "countpostalcode", params)

    async def sms_sendbypostalcode(self, params: dict = {}) -> KavenegarResponse:
        return await self._request("sms", "sendbypostalcode", params)

    async def verify_lookup(self, params: dict = {}) -> KavenegarResponse:
        return await self._request("verify", "lookup", params)

    async def call_maketts(self, params: dict = {}) -> KavenegarResponse:
        return await self._request("call", "maketts", params)

    async def call_status(self, params: dict = {}) -> KavenegarResponse:
        return await self._request("call", "status", params)

    async def account_info(self) -> KavenegarResponse:
        return await self._request("account", "info")

    async def account_config(self, params: dict = {}) -> KavenegarResponse:
        return await self._request("account", "config", params)
