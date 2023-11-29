import { lazy } from "react";
import type { Path } from "react-router-dom";
import { generateEncodedPath } from "../../utils/generateEncodedPath";
import type { AppRouteObject } from "../../routes";

export type IdentityProviderEidasSamlParams = { realm: string };

const AddEidasSamlConnect = lazy(() => import("../add/AddEidasSamlConnect"));

export const IdentityProviderEidasSamlRoute: AppRouteObject = {
  path: "/:realm/identity-providers/eidas-saml/add",
  element: <AddEidasSamlConnect />,
  breadcrumb: (t) => t("addEidasSamlProvider"),
  handle: {
    access: "manage-identity-providers",
  },
};

export const toIdentityProviderEidasSaml = (
  params: IdentityProviderEidasSamlParams,
): Partial<Path> => ({
  pathname: generateEncodedPath(IdentityProviderEidasSamlRoute.path, params),
});