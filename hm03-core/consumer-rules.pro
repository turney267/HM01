# Consumer ProGuard rules for hm03-core public API entry points
-keep public class dev.hm03.browser.IntentBrowserActivity {
    public *;
}
-keep public class dev.hm03.browser.MinimalCustomTabsService {
    public *;
}
-keep public class dev.hm03.browser.config.** {
    public protected *;
}
-keep public class dev.hm03.browser.dns.** {
    public protected *;
}
-keep public class dev.hm03.browser.filter.** {
    public protected *;
}
-keep public class dev.hm03.browser.ui.** {
    public protected *;
}
