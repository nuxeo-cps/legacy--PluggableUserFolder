#
# This is for testing the patching of CMF. This means the tests
# must know if CMF and CPS are installed or not. Complicated stuff.
#

import os, sys
if __name__ == '__main__':
    execfile(os.path.join(sys.path[0], 'framework.py'))

#os.environ['STUPID_LOG_FILE'] = os.path.join(os.getcwd(), 'zLOG.log')
#os.environ['STUPID_LOG_SEVERITY'] = '-200'  # DEBUG

from testUserFolder import TestBase
from Products.PluggableUserFolder.CMFPatch import mergedLocalRoles

# It's only possible to test the CMF patching if CMF is installed and CPS not.
test_cmf_support = 0
try:
    from Products import CMFCore
    try:
        from Products import CPSCore
    except ImportError:
        test_cmf_support = 1
except ImportError:
    pass

class TestCMFPatch(TestBase):

    def testPatching(self):
        # Make sure it's patched correctly
        self.failUnless(CMFCore.utils.mergedLocalRoles is mergedLocalRoles)


if __name__ == '__main__':
    framework(descriptions=0, verbosity=1)
else:
    import unittest
    def test_suite():
        suite = unittest.TestSuite()
        if test_cmf_support:
            suite.addTest(unittest.makeSuite(TestCMFPatch))
        return suite

