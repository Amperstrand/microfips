"""Client-side labgrid resource classes for microfips bench tokens.

The exporter->coordinator wire only carries flat scalar params (protobuf
MapValue), so these classes exist purely on the client and carry no
device logic — presence detection stays with HIL preflight (sysfs/udev),
and acquisition is an exclusivity token, not a port export. Pattern:
bolty-rs tools/hil/labgrid_resources.py. Imported by labgrid-env.yaml
(`imports:`).
"""

import attr

from labgrid import target_factory
from labgrid.resource.common import Resource


@target_factory.reg_resource
@attr.s(eq=False)
class BenchSerialToken(Resource):
    """A bench board's serial interface as a coordinator-visible token."""

    usb_serial = attr.ib(default="", validator=attr.validators.instance_of(str))
    vidpid = attr.ib(default="", validator=attr.validators.instance_of(str))
    id_path = attr.ib(default="", validator=attr.validators.instance_of(str))
