# Generated manually due to missing grpc_tools in environment.
"""gRPC stubs for pkd_service.proto."""

import grpc
from google.protobuf import empty_pb2 as google_dot_protobuf_dot_empty__pb2

from . import pkd_service_pb2 as pkd__service__pb2


class PKDServiceStub(object):
    """Stub client for PKDService."""

    def __init__(self, channel: grpc.Channel) -> None:
        self.ListTrustAnchors = channel.unary_unary(
            "/pkd.PKDService/ListTrustAnchors",
            request_serializer=google_dot_protobuf_dot_empty__pb2.Empty.SerializeToString,
            response_deserializer=pkd__service__pb2.ListTrustAnchorsResponse.FromString,
        )
        self.Sync = channel.unary_unary(
            "/pkd.PKDService/Sync",
            request_serializer=pkd__service__pb2.SyncRequest.SerializeToString,
            response_deserializer=pkd__service__pb2.SyncResponse.FromString,
        )


class PKDServiceServicer(object):
    """Server-side implementation base class."""

    def ListTrustAnchors(self, request, context):  # pylint: disable=unused-argument
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details("Method not implemented!")
        raise NotImplementedError("Method not implemented!")

    def Sync(self, request, context):  # pylint: disable=unused-argument
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details("Method not implemented!")
        raise NotImplementedError("Method not implemented!")


def add_PKDServiceServicer_to_server(servicer, server):
    rpc_method_handlers = {
        "ListTrustAnchors": grpc.unary_unary_rpc_method_handler(
            servicer.ListTrustAnchors,
            request_deserializer=google_dot_protobuf_dot_empty__pb2.Empty.FromString,
            response_serializer=pkd__service__pb2.ListTrustAnchorsResponse.SerializeToString,
        ),
        "Sync": grpc.unary_unary_rpc_method_handler(
            servicer.Sync,
            request_deserializer=pkd__service__pb2.SyncRequest.FromString,
            response_serializer=pkd__service__pb2.SyncResponse.SerializeToString,
        ),
    }
    generic_handler = grpc.method_handlers_generic_handler("pkd.PKDService", rpc_method_handlers)
    server.add_generic_rpc_handlers((generic_handler,))


__all__ = [
    "PKDServiceStub",
    "PKDServiceServicer",
    "add_PKDServiceServicer_to_server",
]
