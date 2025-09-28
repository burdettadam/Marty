"""Common gRPC server interceptors."""

from __future__ import annotations

import logging
from typing import Callable, Optional

import grpc

from marty_common.exceptions import MartyServiceException

LOGGER = logging.getLogger(__name__)


class ExceptionToStatusInterceptor(grpc.ServerInterceptor):
    """Translate application exceptions into canonical gRPC status codes."""

    def intercept_service(self, continuation, handler_call_details):  # type: ignore[override]
        handler = continuation(handler_call_details)
        if handler is None:
            return None

        if handler.unary_unary:
            return grpc.unary_unary_rpc_method_handler(
                self._wrap_unary_unary(handler.unary_unary),
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )

        if handler.unary_stream:
            return grpc.unary_stream_rpc_method_handler(
                self._wrap_unary_stream(handler.unary_stream),
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )

        if handler.stream_unary:
            return grpc.stream_unary_rpc_method_handler(
                self._wrap_stream_unary(handler.stream_unary),
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )

        if handler.stream_stream:
            return grpc.stream_stream_rpc_method_handler(
                self._wrap_stream_stream(handler.stream_stream),
                request_deserializer=handler.request_deserializer,
                response_serializer=handler.response_serializer,
            )

        return handler

    def _wrap_unary_unary(self, func: Callable):
        def _wrapper(request, context):
            try:
                return func(request, context)
            except MartyServiceException as exc:  # pylint: disable=except-general
                LOGGER.warning("Application error: %s", exc)
                context.abort(exc.status_code or grpc.StatusCode.INTERNAL, exc.message)
            except grpc.RpcError:
                raise
            except Exception as exc:  # pylint: disable=broad-except
                LOGGER.exception("Unhandled server exception")
                context.abort(grpc.StatusCode.INTERNAL, str(exc))

        return _wrapper

    def _wrap_unary_stream(self, func: Callable):
        def _wrapper(request, context):
            try:
                yield from func(request, context)
            except MartyServiceException as exc:  # pylint: disable=except-general
                LOGGER.warning("Application error: %s", exc)
                context.abort(exc.status_code or grpc.StatusCode.INTERNAL, exc.message)
            except grpc.RpcError:
                raise
            except Exception as exc:  # pylint: disable=broad-except
                LOGGER.exception("Unhandled server exception")
                context.abort(grpc.StatusCode.INTERNAL, str(exc))

        return _wrapper

    def _wrap_stream_unary(self, func: Callable):
        def _wrapper(request_iterator, context):
            try:
                return func(request_iterator, context)
            except MartyServiceException as exc:  # pylint: disable=except-general
                LOGGER.warning("Application error: %s", exc)
                context.abort(exc.status_code or grpc.StatusCode.INTERNAL, exc.message)
            except grpc.RpcError:
                raise
            except Exception as exc:  # pylint: disable=broad-except
                LOGGER.exception("Unhandled server exception")
                context.abort(grpc.StatusCode.INTERNAL, str(exc))

        return _wrapper

    def _wrap_stream_stream(self, func: Callable):
        def _wrapper(request_iterator, context):
            try:
                yield from func(request_iterator, context)
            except MartyServiceException as exc:  # pylint: disable=except-general
                LOGGER.warning("Application error: %s", exc)
                context.abort(exc.status_code or grpc.StatusCode.INTERNAL, exc.message)
            except grpc.RpcError:
                raise
            except Exception as exc:  # pylint: disable=broad-except
                LOGGER.exception("Unhandled server exception")
                context.abort(grpc.StatusCode.INTERNAL, str(exc))

        return _wrapper


__all__ = ["ExceptionToStatusInterceptor"]
