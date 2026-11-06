# Consumer ProGuard rules for hm01-core public API entry points
-keep public class dev.hm01.browser.IntentBrowserActivity {
    public *;
}
-keep public class dev.hm01.browser.MinimalCustomTabsService {
    public *;
}
-keep public class dev.hm01.browser.config.** {
    public protected *;
}
-keep public class dev.hm01.browser.dns.** {
    public protected *;
}
-keep public class dev.hm01.browser.filter.** {
    public protected *;
}
-keep public class dev.hm01.browser.ui.** {
    public protected *;
}
