SECTIONS {
  /* Start section */
  __TEXT.__aws_lc_start : {
    *(__TEXT.__aws_lc_start)
    PROVIDE(__aws_lc_fips_start = .);
  }
  
  /* FIPS code */
  __TEXT.__aws_lc_fips_text : {
    *(__TEXT.__aws_lc_fips_text)
    *(__TEXT.__aws_lc_fips_text.*)
  }
  
  /* FIPS data */
  __DATA.__aws_lc_fips_data : {
    *(__DATA.__aws_lc_fips_data)
    *(__DATA.__aws_lc_fips_data.*)
  }
  
  /* End section with HMAC */
  __TEXT.__aws_lc_end : {
    PROVIDE(___aws_lc_fips_hmac = .);
    . = . + 32;
    *(__TEXT.__aws_lc_end)
    PROVIDE(___aws_lc_fips_end = .);
  }
}