from django.test import TestCase, Client
from django.urls import reverse
from scanner.models import Program, ScanRun, Asset, Endpoint, Port, Signal
from scanner.services.runner import (
    ScopeBridge,
    upsert_asset_orm,
    upsert_endpoint_orm,
    upsert_port_orm,
    upsert_signal_orm,
)


class TestProgramScopeGuard(TestCase):
    def setUp(self):
        self.program = Program.objects.create(
            name="Test Program",
            in_scope="*.example.com\nexample.com",
            out_of_scope="admin.example.com\n*.internal.example.com",
            rate_limit=5,
            concurrency=2,
            timeout=30,
        )

    def test_in_scope_allowed(self):
        self.assertTrue(self.program.is_host_allowed("example.com"))
        self.assertTrue(self.program.is_host_allowed("app.example.com"))
        self.assertTrue(self.program.is_host_allowed("api.v1.example.com"))

    def test_out_of_scope_overrides_in_scope(self):
        # Invariant 2: out_of_scope always takes precedence over in_scope
        self.assertFalse(self.program.is_host_allowed("admin.example.com"))
        self.assertFalse(self.program.is_host_allowed("secret.internal.example.com"))

    def test_unrelated_hosts_blocked(self):
        self.assertFalse(self.program.is_host_allowed("attacker.com"))
        self.assertFalse(self.program.is_host_allowed("notexample.com"))
        self.assertFalse(self.program.is_host_allowed("example.com.evil.org"))

    def test_url_allowed_checks_hostname(self):
        self.assertTrue(self.program.is_url_allowed("https://app.example.com:8443/login?user=1"))
        self.assertFalse(self.program.is_url_allowed("https://admin.example.com/login"))
        self.assertFalse(self.program.is_url_allowed("https://evil.com/redirect"))


class TestOrmUpsertAndDiffing(TestCase):
    def setUp(self):
        self.program = Program.objects.create(
            name="Diffing Program",
            in_scope="*.test.com\ntest.com",
        )
        self.run1 = ScanRun.objects.create(
            program=self.program,
            run_id="20261125-000001",
            scan_type="wide",
            status="completed"
        )
        self.run2 = ScanRun.objects.create(
            program=self.program,
            run_id="20261125-000002",
            scan_type="wide",
            status="completed"
        )
        self.run3 = ScanRun.objects.create(
            program=self.program,
            run_id="20261125-000003",
            scan_type="wide",
            status="running"
        )

    def test_asset_new_and_reactivated(self):
        # 1. Seen in run 1
        asset, created = upsert_asset_orm(self.program, self.run1, None, {
            "host": "a.test.com", "url": "https://a.test.com", "status": 200, "tech": ["nginx"], "title": "Home"
        })
        self.assertTrue(created)
        self.assertEqual(asset.first_run, self.run1)
        self.assertEqual(asset.last_run, self.run1)
        self.assertIsNone(asset.react_run)

        # 2. Absent in run 2 (we do not upsert it in run 2)

        # 3. Present again in run 3 with previous completed run being run 2
        asset, created = upsert_asset_orm(self.program, self.run3, self.run2, {
            "host": "a.test.com", "url": "https://a.test.com", "status": 200, "tech": ["nginx"], "title": "Home"
        })
        self.assertFalse(created)
        self.assertEqual(asset.first_run, self.run1)
        self.assertEqual(asset.last_run, self.run3)
        self.assertEqual(asset.react_run, self.run3)  # Reactivated!

    def test_out_of_scope_asset_never_saved(self):
        # Invariant 1: no data outside scope is saved
        asset, created = upsert_asset_orm(self.program, self.run1, None, {
            "host": "evil.com", "url": "https://evil.com", "status": 200
        })
        self.assertIsNone(asset)
        self.assertFalse(created)
        self.assertEqual(Asset.objects.count(), 0)

    def test_endpoint_scoring_and_normalization(self):
        endpoint, created = upsert_endpoint_orm(
            self.program, self.run1, None,
            shape="https://app.test.com/api/v1/user/{n}",
            example="https://app.test.com/api/v1/user/101?user_id=101",
            params=["user_id"]
        )
        self.assertTrue(created)
        # sensitive-path (api, user) + has-params + idor-like-param
        self.assertGreater(endpoint.score, 0)
        self.assertIn("idor-like-param", endpoint.why)


class TestWebViews(TestCase):
    def setUp(self):
        self.client = Client()
        self.program = Program.objects.create(
            name="Web Target",
            in_scope="*.webtarget.com",
            out_of_scope="corp.webtarget.com",
            rate_limit=10,
        )

    def test_program_list_view(self):
        resp = self.client.get(reverse('program_list'))
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "Web Target")

    def test_program_detail_view(self):
        resp = self.client.get(reverse('program_detail', kwargs={'pk': self.program.pk}))
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "webtarget.com")

    def test_program_create_view(self):
        resp = self.client.post(reverse('program_create'), {
            'name': 'New Program Scope',
            'in_scope': '*.newscope.org\nnewscope.org',
            'out_of_scope': 'admin.newscope.org',
            'rate_limit': 5,
            'concurrency': 2,
            'timeout': 300,
        })
        self.assertEqual(resp.status_code, 302)  # Redirects to detail
        self.assertTrue(Program.objects.filter(name='New Program Scope').exists())

    def test_narrow_scan_rejects_out_of_scope(self):
        resp = self.client.post(reverse('trigger_scan', kwargs={'pk': self.program.pk}), {
            'scan_type': 'narrow',
            'target': 'https://corp.webtarget.com/login',  # Out of scope!
        }, follow=True)
        self.assertContains(resp, "OUT OF SCOPE")
        self.assertEqual(ScanRun.objects.count(), 0)

    def test_export_scope_json(self):
        resp = self.client.get(reverse('export_scope_json', kwargs={'pk': self.program.pk}))
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp['Content-Type'], 'application/json')
        self.assertIn('*.webtarget.com', resp.content.decode())

    def test_stop_scan_view(self):
        scan_run = ScanRun.objects.create(
            program=self.program,
            run_id="20261125-999999",
            scan_type="wide",
            status="running"
        )
        resp = self.client.post(reverse('stop_scan', kwargs={'pk': scan_run.pk}))
        self.assertEqual(resp.status_code, 302)
        scan_run.refresh_from_db()
        self.assertEqual(scan_run.status, 'stopped')
        self.assertIn("stopped by user", scan_run.log_output)
