from carthage import base_injector, inject, Injector
from layout import test_layout

@inject(injector=Injector)
def carthage_plugin(injector):
    injector.add_provider(test_layout)
    
