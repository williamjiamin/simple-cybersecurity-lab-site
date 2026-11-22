# Private draft review checklist

- [ ] Obtain the exact three publishing HTML files and stylesheet from the owner-controlled repository.
- [ ] Apply the additive patch to an isolated working tree and confirm all current website files remain unchanged.
- [ ] Run the local auditor and address the HTML and CSP findings against actual files.
- [ ] Confirm that the optional meta CSP does not block existing legitimate styles, images, or interactions.
- [ ] Capture HTTP response headers from each published HTML route and run the strict header check.
- [ ] Mark unsupported server-header controls as deployment limitations if the serving layer is not configurable.
- [ ] Manually verify keyboard traversal, visible focus, screen-reader output, responsive layout, reduced motion, and contrast.
- [ ] Verify the native consumer implements the ON-by-default lab flag and an OFF mode that does not mutate existing runtime state, if the separate app integration is undertaken.
- [ ] Keep all artifacts private until an explicit release authorization. No deployment or publication is part of this order.
