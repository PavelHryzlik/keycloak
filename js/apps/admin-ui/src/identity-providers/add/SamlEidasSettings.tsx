import IdentityProviderRepresentation from "@keycloak/keycloak-admin-client/lib/defs/identityProviderRepresentation";
import {
  FormGroup,
  Select,
  SelectOption,
  SelectVariant
} from "@patternfly/react-core";
import { useState } from "react";
import { Controller, useFormContext } from "react-hook-form";
import { useTranslation } from "react-i18next";
import { HelpItem } from "ui-shared";
import { KeycloakTextArea } from "../../components/keycloak-text-area/KeycloakTextArea";
import { SwitchField } from "../component/SwitchField";

export const SamlEidasSettings = () => {
  const { t } = useTranslation();
  const {
    register,
    control
  } = useFormContext<IdentityProviderRepresentation>();
  const [levelOfAssuranceDropdownOpen, setLevelOfAssuranceDropdownOpen] =
    useState(false);

  return (
    <>
      <FormGroup
        label={t("levelOfAssurance")}
        labelIcon={
          <HelpItem
            helpText={t("levelOfAssuranceHelp")}
            fieldLabelId="levelOfAssurance"
          />
        }
        fieldId="kc-levelOfAssurance"
        helperTextInvalid={t("required")}
      >
        <Controller
          name="config.levelOfAssurance"
          defaultValue={t("levelOfAssuranceLoALow")}
          control={control}
          render={({ field }) => (
            <Select
              toggleId="kc-levelOfAssurance"
              onToggle={(isExpanded) =>
                setLevelOfAssuranceDropdownOpen(isExpanded)
              }
              isOpen={levelOfAssuranceDropdownOpen}
              onSelect={(_, value) => {
                field.onChange(value.toString());
                setLevelOfAssuranceDropdownOpen(false);
              }}
              selections={field.value}
              variant={SelectVariant.single}
            >
              <SelectOption
                data-testid="levelOfAssuranceLoALow-option"
                value="http://eidas.europa.eu/LoA/low"
                isPlaceholder
              >
                {t("levelOfAssuranceLoALow")}
              </SelectOption>
              <SelectOption
                data-testid="levelOfAssuranceLoASubstantial-option"
                value="http://eidas.europa.eu/LoA/substantial"
              >
                {t("levelOfAssuranceLoASubstantial")}
              </SelectOption>
              <SelectOption
                data-testid="levelOfAssuranceLoAHigh-option"
                value="http://eidas.europa.eu/LoA/high"
              >
                {t("levelOfAssuranceLoAHigh")}
              </SelectOption>
            </Select>
          )}
        ></Controller>
      </FormGroup>

      <SwitchField
        field="config.privateServiceProvider"
        label="privateServiceProvider"
      />

      <FormGroup
        label={t("requestedAttributes")}
        fieldId="kc-requested-attributes"
        labelIcon={
          <HelpItem
            helpText={t("requestedAttributesHelp")}
            fieldLabelId="requestedAttributes"
          />
        }
      >
        <KeycloakTextArea
            id="kc-requested-attributes"
            {...register("config.requestedAttributes")}
          ></KeycloakTextArea>
      </FormGroup> 
    </>
  );
};