from contextlib import contextmanager

@contextmanager
def setup(tmp, root, config):
    yield config.replace('"workflow_policy.toml"', '"' + (root/"workflow_policy.toml").as_posix() + '"')


def check(effect):
    assert effect["artifact"] == {"location_totals":{"NORTH":6,"SOUTH":3},"zero_quantity_rows":["r2"]}
