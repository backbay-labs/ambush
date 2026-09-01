-- The dogfood application profile identifier is ambush-ios-dogfood, matching
-- the App Attest application id and the mobile bundle's profile registry.
UPDATE push_gateway_installations
    SET app_profile = 'ambush-ios-dogfood'
    WHERE app_profile = 'buzz-ios-dogfood';

ALTER TABLE push_gateway_installations
    DROP CONSTRAINT push_gateway_installations_app_profile_check;
ALTER TABLE push_gateway_installations
    ADD CONSTRAINT push_gateway_installations_app_profile_check
    CHECK (app_profile = 'ambush-ios-dogfood');
