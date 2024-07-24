import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;


public class BurpHttpx implements BurpExtension {
    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("Copy as httpx");
        api.userInterface().registerContextMenuItemsProvider(new HttpxContentMenuItemsProvider(api));
    }



}
