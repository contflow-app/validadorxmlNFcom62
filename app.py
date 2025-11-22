import io
from typing import List, Dict, Any

import streamlit as st
import pandas as pd
import yaml
from lxml import etree
import re


# =========================
# Helpers de namespace NFCom
# =========================

def get_ns(tree: etree._ElementTree) -> Dict[str, str]:
    """
    Retorna o namespace padrão do NFCom mapeado como prefixo 'n'.
    Se não houver namespace, retorna {}.
    """
    root = tree.getroot()
    default_ns = root.nsmap.get(None)
    return {"n": default_ns} if default_ns else {}


# =========================
# Configuração inicial
# =========================

st.set_page_config(page_title="Validador NFCom 62", layout="wide")


# =========================
# Carregamento de arquivos de configuração
# =========================

@st.cache_data
def load_rules(path: str = "rules.yaml") -> List[Dict[str, Any]]:
    """Carrega as regras de validação a partir de um arquivo YAML."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            rules = yaml.safe_load(f) or []
    except FileNotFoundError:
        st.warning(f"Arquivo de regras '{path}' não encontrado. Nenhuma regra carregada.")
        rules = []
    return rules


@st.cache_data
def load_cclass_config(path: str = "cclass_config.yaml") -> Dict[str, Any]:
    """Carrega configuração de CClass (SCM/SVA) a partir de YAML."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            cfg = yaml.safe_load(f) or {}
    except FileNotFoundError:
        st.warning(f"Arquivo de configuração de CClass '{path}' não encontrado. Usando configuração padrão.")
        cfg = {}
    return cfg


# =========================
# Funções auxiliares XML
# =========================

def parse_xml(file_bytes: bytes) -> etree._ElementTree:
    """
    Faz o parse do XML e retorna um ElementTree.
    Lança ValueError se o arquivo não for XML válido.
    """
    try:
        parser = etree.XMLParser(remove_blank_text=True)
        tree = etree.parse(io.BytesIO(file_bytes), parser)
        return tree
    except Exception as e:
        raise ValueError(f"XML inválido: {e}")


def get_xpath_nodes(tree: etree._ElementTree, xpath: str):
    """
    Executa um XPath no XML de NFCom considerando o namespace padrão.
    Usa o prefixo 'n' para o namespace 'http://www.portalfiscal.inf.br/nfcom'.
    """
    root = tree.getroot()
    ns = get_ns(tree)
    if ns:
        return root.xpath(xpath, namespaces=ns)
    return root.xpath(xpath)


def get_nf_model(tree: etree._ElementTree) -> str:
    """Retorna o valor de ide/mod (modelo da NF)."""
    ns = get_ns(tree)
    root = tree.getroot()
    if ns:
        nodes = root.xpath(".//n:ide/n:mod", namespaces=ns)
    else:
        nodes = root.xpath(".//ide/mod")
    return (nodes[0].text or "").strip() if nodes else ""


# =========================
# Motor genérico de regras (rules.yaml)
# =========================

def apply_rule_to_node(rule: Dict[str, Any], node, file_name: str) -> List[Dict[str, Any]]:
    """
    Aplica uma regra simples (obrigatorio, regex, lista_valores) a um nó específico.
    Retorna lista de dicionários de erros.
    """
    erros: List[Dict[str, Any]] = []
    rule_type = rule.get("tipo")

    if rule_type == "regex":
        texto = (node.text or "").strip()
        pattern = rule.get("parametros", {}).get("pattern", "")
        if pattern and not re.match(pattern, texto):
            erros.append({
                "arquivo": file_name,
                "regra_id": rule.get("id"),
                "descricao_regra": rule.get("descricao"),
                "campo_xpath": rule.get("xpath"),
                "valor_encontrado": texto,
                "mensagem_erro": rule.get("mensagem_erro"),
                "sugestao_correcao": rule.get("sugestao_correcao"),
                "nivel": rule.get("nivel", "erro"),
            })

    elif rule_type == "obrigatorio":
        texto = (node.text or "").strip() if node is not None else ""
        if not texto:
            erros.append({
                "arquivo": file_name,
                "regra_id": rule.get("id"),
                "descricao_regra": rule.get("descricao"),
                "campo_xpath": rule.get("xpath"),
                "valor_encontrado": texto,
                "mensagem_erro": rule.get("mensagem_erro"),
                "sugestao_correcao": rule.get("sugestao_correcao"),
                "nivel": rule.get("nivel", "erro"),
            })

    elif rule_type == "lista_valores":
        texto = (node.text or "").strip()
        valores_permitidos = rule.get("parametros", {}).get("valores_permitidos", [])
        if valores_permitidos and texto not in valores_permitidos:
            erros.append({
                "arquivo": file_name,
                "regra_id": rule.get("id"),
                "descricao_regra": rule.get("descricao"),
                "campo_xpath": rule.get("xpath"),
                "valor_encontrado": texto,
                "mensagem_erro": rule.get("mensagem_erro"),
                "sugestao_correcao": rule.get("sugestao_correcao"),
                "nivel": rule.get("nivel", "erro"),
            })

    return erros


def validate_with_rules_yaml(
    tree: etree._ElementTree,
    rules: List[Dict[str, Any]],
    file_name: str
) -> List[Dict[str, Any]]:
    """
    Aplica todas as regras definidas em rules.yaml a um XML.
    Suporta tipos: obrigatorio, regex, lista_valores, condicional.
    """
    all_errors: List[Dict[str, Any]] = []
    root = tree.getroot()
    ns = get_ns(tree)

    for rule in rules:
        rule_type = rule.get("tipo")
        xpath = rule.get("xpath", "")
        params = rule.get("parametros", {}) or {}

        if rule_type == "condicional":
            base_xpath = xpath or ".//n:det"
            cond_xpath = params.get("condicao_xpath")
            cond_values = params.get("condicao_valores", [])
            alvo_xpath = params.get("alvo_xpath")
            alvo_valor_esperado = params.get("alvo_valor_esperado")
            obrigatorio = params.get("alvo_obrigatorio", True)

            if ns:
                base_nodes = root.xpath(base_xpath, namespaces=ns)
            else:
                base_nodes = root.xpath(base_xpath)

            for base_node in base_nodes:
                # condição
                if cond_xpath:
                    if ns:
                        cond_nodes = base_node.xpath(cond_xpath, namespaces=ns)
                    else:
                        cond_nodes = base_node.xpath(cond_xpath)
                    cond_text = (cond_nodes[0].text or "").strip() if cond_nodes else ""
                else:
                    cond_text = ""

                if cond_values and cond_text not in cond_values:
                    continue

                # alvo
                if alvo_xpath:
                    if ns:
                        alvo_nodes = base_node.xpath(alvo_xpath, namespaces=ns)
                    else:
                        alvo_nodes = base_node.xpath(alvo_xpath)
                    alvo_text = (alvo_nodes[0].text or "").strip() if alvo_nodes else ""
                else:
                    alvo_nodes = []
                    alvo_text = ""

                erro = False

                if alvo_valor_esperado is not None:
                    if alvo_text != str(alvo_valor_esperado):
                        erro = True
                else:
                    if obrigatorio and not alvo_text:
                        erro = True
                    if not obrigatorio and alvo_text:
                        erro = True

                if erro:
                    all_errors.append({
                        "arquivo": file_name,
                        "regra_id": rule.get("id"),
                        "descricao_regra": rule.get("descricao"),
                        "campo_xpath": f"{base_xpath}/{alvo_xpath}",
                        "valor_encontrado": alvo_text,
                        "mensagem_erro": rule.get("mensagem_erro"),
                        "sugestao_correcao": rule.get("sugestao_correcao"),
                        "nivel": rule.get("nivel", "erro"),
                    })

        elif rule_type in ("obrigatorio", "regex", "lista_valores"):
            nodes = get_xpath_nodes(tree, xpath)
            if not nodes and rule_type == "obrigatorio":
                all_errors.append({
                    "arquivo": file_name,
                    "regra_id": rule.get("id"),
                    "descricao_regra": rule.get("descricao"),
                    "campo_xpath": xpath,
                    "valor_encontrado": "",
                    "mensagem_erro": rule.get("mensagem_erro"),
                    "sugestao_correcao": rule.get("sugestao_correcao"),
                    "nivel": rule.get("nivel", "erro"),
                })
            else:
                for node in nodes:
                    all_errors.extend(apply_rule_to_node(rule, node, file_name))

    return all_errors


# =========================
# Regras customizadas em Python
# =========================

def is_dest_pf_or_pj_nao_contrib(tree: etree._ElementTree) -> bool:
    """
    Identifica se o destinatário é:
      - Pessoa Física; ou
      - Pessoa Jurídica não contribuinte de ICMS.
    Baseado em CPF/CNPJ + indIEDest.
    """
    root = tree.getroot()
    ns = get_ns(tree)
    dests = root.xpath(".//n:dest", namespaces=ns) if ns else root.xpath(".//dest")
    if not dests:
        return False

    dest = dests[0]
    if ns:
        cpf_nodes = dest.xpath("./n:CPF", namespaces=ns)
        cnpj_nodes = dest.xpath("./n:CNPJ", namespaces=ns)
        ind_nodes = dest.xpath("./n:indIEDest", namespaces=ns)
    else:
        cpf_nodes = dest.xpath("./CPF")
        cnpj_nodes = dest.xpath("./CNPJ")
        ind_nodes = dest.xpath("./indIEDest")

    cpf = (cpf_nodes[0].text or "").strip() if cpf_nodes else ""
    cnpj = (cnpj_nodes[0].text or "").strip() if cnpj_nodes else ""
    ind_ie_dest = (ind_nodes[0].text or "").strip() if ind_nodes else ""

    # PF não contribuinte
    if cpf and (not ind_ie_dest or ind_ie_dest in ("2", "9")):
        return True

    # PJ não contribuinte (CNPJ + indIEDest = 9)
    if cnpj and ind_ie_dest == "9":
        return True

    return False


def validate_cfop_pf_pj_nao_contrib(
    tree: etree._ElementTree,
    file_name: str,
    cclass_cfg: Dict[str, Any]
) -> List[Dict[str, Any]]:
    """
    Regra fiscal interna:
    - Se destinatário for PF ou PJ NÃO contribuinte de ICMS,
      então, para itens que NÃO são SVA, o CFOP deve ser:
         5307 (operações internas) ou
         6307 (operações interestaduais).

    Itens SVA (cClass na lista sva_cclasses) são ignorados aqui,
    pois já seguem a regra própria de SVA (sem CFOP / CFOP zerado).
    """
    erros: List[Dict[str, Any]] = []

    if not is_dest_pf_or_pj_nao_contrib(tree):
        return erros  # não se aplica

    root = tree.getroot()
    ns = get_ns(tree)

    sva_cclasses = cclass_cfg.get("sva_cclasses", [])

    # UF emitente e destinatário
    if ns:
        uf_emit_nodes = root.xpath(".//n:emit/n:enderEmit/n:UF", namespaces=ns)
        uf_dest_nodes = root.xpath(".//n:dest/n:enderDest/n:UF", namespaces=ns)
        det_nodes = root.xpath(".//n:det", namespaces=ns)
    else:
        uf_emit_nodes = root.xpath(".//emit/enderEmit/UF")
        uf_dest_nodes = root.xpath(".//dest/enderDest/UF")
        det_nodes = root.xpath(".//det")

    uf_emit = (uf_emit_nodes[0].text or "").strip() if uf_emit_nodes else ""
    uf_dest = (uf_dest_nodes[0].text or "").strip() if uf_dest_nodes else ""

    if uf_emit and uf_dest and uf_emit == uf_dest:
        cfop_corretos = ["5307"]
    else:
        cfop_corretos = ["6307"]

    for det in det_nodes:
        # Lê cClass e CFOP do item
        if ns:
            cclass_nodes = det.xpath("./n:prod/n:cClass", namespaces=ns)
            cfop_nodes = det.xpath("./n:prod/n:CFOP", namespaces=ns)
        else:
            cclass_nodes = det.xpath("./prod/cClass")
            cfop_nodes = det.xpath("./prod/CFOP")

        cclass_text = (cclass_nodes[0].text or "").strip() if cclass_nodes else ""
        cfop = (cfop_nodes[0].text or "").strip() if cfop_nodes else ""

        # Se for SVA, não aplica essa regra (já tem regra própria)
        if cclass_text in sva_cclasses:
            continue

        if cfop not in cfop_corretos:
            erros.append({
                "arquivo": file_name,
                "regra_id": "R_CFOP_PF_NCONTRIB",
                "descricao_regra": "PF/PJ não contribuinte: CFOP deve ser 5307 (interno) ou 6307 (interestadual)",
                "campo_xpath": ".//det/prod/CFOP",
                "valor_encontrado": cfop,
                "mensagem_erro": f"CFOP '{cfop}' incompatível com destinatário PF/PJ não contribuinte.",
                "sugestao_correcao": f"Ajustar CFOP para {', '.join(cfop_corretos)} conforme UF do emitente e destinatário.",
                "nivel": "erro",
            })

    return erros


def validate_sva_cfop_zero(
    tree: etree._ElementTree,
    file_name: str,
    cclass_cfg: Dict[str, Any]
) -> List[Dict[str, Any]]:
    """
    Regra:
    - Se o cClass do item estiver na lista de SVA (cclass_config.yaml),
      então o CFOP deve estar "zerado".
    Implementação:
      - Se não houver CFOP informado: OK (consideramos zerado).
      - Se houver CFOP e for diferente de cfop_sva_zerado (default "0000"): ERRO.
    """
    erros: List[Dict[str, Any]] = []

    sva_cclasses = cclass_cfg.get("sva_cclasses", [])
    cfop_esperado = cclass_cfg.get("cfop_sva_zerado", "0000")

    if not sva_cclasses:
        return erros

    root = tree.getroot()
    ns = get_ns(tree)
    det_nodes = root.xpath(".//n:det", namespaces=ns) if ns else root.xpath(".//det")

    for det in det_nodes:
        if ns:
            cclass_nodes = det.xpath("./n:prod/n:cClass", namespaces=ns)
            cfop_nodes = det.xpath("./n:prod/n:CFOP", namespaces=ns)
        else:
            cclass_nodes = det.xpath("./prod/cClass")
            cfop_nodes = det.xpath("./prod/CFOP")

        cclass_text = (cclass_nodes[0].text or "").strip() if cclass_nodes else ""
        cfop_text = (cfop_nodes[0].text or "").strip() if cfop_nodes else ""

        if cclass_text not in sva_cclasses:
            continue  # não é SVA

        # Se não tem CFOP, consideramos "zerado" → OK
        if not cfop_text:
            continue

        # Se tem CFOP diferente do esperado, é erro
        if cfop_text != cfop_esperado:
            erros.append({
                "arquivo": file_name,
                "regra_id": "R_SVA_CFOP_ZERO",
                "descricao_regra": "Se cClass for SVA, CFOP não deve ser tributário (deve estar 'zerado')",
                "campo_xpath": ".//det/prod/CFOP",
                "valor_encontrado": cfop_text,
                "mensagem_erro": f"CFOP '{cfop_text}' incorreto para item SVA (cClass={cclass_text}).",
                "sugestao_correcao": (
                    f"Remover o CFOP do item SVA ou, se necessário, parametrizar como '{cfop_esperado}' "
                    "conforme política fiscal do escritório."
                ),
                "nivel": "erro",
            })

    return erros


def validate_custom_rules(
    tree: etree._ElementTree,
    file_name: str,
    cclass_cfg: Dict[str, Any]
) -> List[Dict[str, Any]]:
    """
    Aplica regras customizadas em Python que vão além do YAML.
    """
    erros: List[Dict[str, Any]] = []

    # CFOP para PF/PJ não contribuinte (ignorando SVA)
    erros.extend(validate_cfop_pf_pj_nao_contrib(tree, file_name, cclass_cfg))

    # SVA com CFOP zerado
    erros.extend(validate_sva_cfop_zero(tree, file_name, cclass_cfg))

    return erros


# =========================
# Extração para relatório de faturamento por CClass
# =========================

def extract_faturamento_items(tree: etree._ElementTree, file_name: str) -> List[Dict[str, Any]]:
    """
    Extrai informações de faturamento por item para posterior consolidação por CClass.
    Para NFCom, usa:
      - cClass  em det/prod/cClass
      - vServ   ~ det/prod/vProd
      - Impostos (se existirem) em det/imposto/PIS, det/imposto/COFINS, det/imposto/ICMS ou ICMSSN.

    Ajuste os XPaths se o layout dos seus XMLs diferir.
    """
    itens: List[Dict[str, Any]] = []

    root = tree.getroot()
    ns = get_ns(tree)
    det_nodes = root.xpath(".//n:det", namespaces=ns) if ns else root.xpath(".//det")

    def to_float(value: str) -> float:
        try:
            return float(value.replace(",", "."))
        except Exception:
            return 0.0

    for det in det_nodes:
        if ns:
            cclass_nodes = det.xpath("./n:prod/n:cClass", namespaces=ns)
            vprod_nodes = det.xpath("./n:prod/n:vProd", namespaces=ns)

            vpis_nodes = det.xpath("./n:imposto/n:PIS/n:vPIS", namespaces=ns)
            vcofins_nodes = det.xpath("./n:imposto/n:COFINS/n:vCOFINS", namespaces=ns)
            vicms_nodes = det.xpath("./n:imposto/n:ICMS/n:vICMS", namespaces=ns)
        else:
            cclass_nodes = det.xpath("./prod/cClass")
            vprod_nodes = det.xpath("./prod/vProd")
            vpis_nodes = det.xpath("./imposto/PIS/vPIS")
            vcofins_nodes = det.xpath("./imposto/COFINS/vCOFINS")
            vicms_nodes = det.xpath("./imposto/ICMS/vICMS")

        cclass = (cclass_nodes[0].text or "").strip() if cclass_nodes else ""
        vserv_text = (vprod_nodes[0].text or "").strip() if vprod_nodes else "0"

        vpis_text = (vpis_nodes[0].text or "").strip() if vpis_nodes else "0"
        vcofins_text = (vcofins_nodes[0].text or "").strip() if vcofins_nodes else "0"
        vicms_text = (vicms_nodes[0].text or "").strip() if vicms_nodes else "0"

        item_data = {
            "arquivo": file_name,
            "cClass": cclass,
            "vServ": to_float(vserv_text),
            "vICMS": to_float(vicms_text),
            "vPIS": to_float(vpis_text),
            "vCOFINS": to_float(vcofins_text),
        }
        itens.append(item_data)

    return itens


# =========================
# Interface Streamlit
# =========================

def main():
    st.title("Validador de NFCom modelo 62 (XML)")
    st.write(
        "Faça o upload de vários arquivos XML de NFCom e gere um relatório de "
        "erros de parametrização e tributação com base nas regras configuradas."
    )

    rules = load_rules()
    cclass_cfg = load_cclass_config()

    st.sidebar.header("Configurações")
    st.sidebar.write(f"Regras (YAML) carregadas: **{len(rules)}**")
    st.sidebar.write("CClass SVA configurados: **{}**".format(
        len(cclass_cfg.get("sva_cclasses", []))
    ))
    consolidar = st.sidebar.checkbox(
        "Consolidar erros iguais em um único agrupamento",
        value=True
    )

    uploaded_files = st.file_uploader(
        "Selecione um ou mais arquivos XML da NFCom",
        type=["xml"],
        accept_multiple_files=True
    )

    if uploaded_files and st.button("Validar arquivos"):
        todos_erros: List[Dict[str, Any]] = []
        erros_arquivos_invalidos: List[Dict[str, Any]] = []
        faturamento_itens: List[Dict[str, Any]] = []

        for f in uploaded_files:
            file_name = f.name
            try:
                content = f.read()
                tree = parse_xml(content)

                # Confere se é modelo 62 (NFCom); se não for, ignora com aviso
                modelo = get_nf_model(tree)
                if modelo and modelo != "62":
                    erros_arquivos_invalidos.append({
                        "arquivo": file_name,
                        "erro": f"Modelo {modelo} diferente de 62 (NFCom). Este validador é exclusivo para NFCom.",
                    })
                    continue

                # Validações genéricas do YAML
                erros_yaml = validate_with_rules_yaml(tree, rules, file_name)
                todos_erros.extend(erros_yaml)

                # Regras customizadas em Python
                erros_custom = validate_custom_rules(tree, file_name, cclass_cfg)
                todos_erros.extend(erros_custom)

                # Dados para faturamento
                itens = extract_faturamento_items(tree, file_name)
                faturamento_itens.extend(itens)

            except ValueError as e:
                erros_arquivos_invalidos.append({
                    "arquivo": file_name,
                    "erro": str(e),
                })

        # Exibe arquivos não processados (XML inválido ou modelo ≠ 62)
        if erros_arquivos_invalidos:
            st.subheader("Arquivos não analisados")
            df_invalidos = pd.DataFrame(erros_arquivos_invalidos)
            st.dataframe(df_invalidos, use_container_width=True)

        # Se não houver nenhum erro de regra
        if not todos_erros:
            st.success("Nenhum erro encontrado de acordo com as regras configuradas.")
        else:
            df_erros = pd.DataFrame(todos_erros)

            tab1, tab2, tab3 = st.tabs([
                "Erros detalhados por arquivo",
                "Erros consolidados",
                "Relatório de faturamento por CClass",
            ])

            # --- Detalhado ---
            with tab1:
                st.subheader("Relatório detalhado por arquivo")
                st.dataframe(df_erros, use_container_width=True)

                csv = df_erros.to_csv(index=False).encode("utf-8-sig")
                st.download_button(
                    "Baixar CSV detalhado de erros",
                    data=csv,
                    file_name="erros_nfcom_detalhado.csv",
                    mime="text/csv"
                )

            # --- Consolidado ---
            with tab2:
                st.subheader("Erros consolidados")
                if consolidar:
                    grouped = (
                        df_erros
                        .groupby([
                            "regra_id",
                            "descricao_regra",
                            "mensagem_erro",
                            "sugestao_correcao",
                            "nivel",
                        ])
                        .agg(
                            qtd_ocorrencias=("arquivo", "count"),
                            arquivos_afetados=("arquivo", lambda x: ", ".join(sorted(set(x)))),
                        )
                        .reset_index()
                    )
                    st.dataframe(grouped, use_container_width=True)

                    csv_g = grouped.to_csv(index=False).encode("utf-8-sig")
                    st.download_button(
                        "Baixar CSV consolidado de erros",
                        data=csv_g,
                        file_name="erros_nfcom_consolidado.csv",
                        mime="text/csv"
                    )
                else:
                    st.info("Marque a opção de consolidação na barra lateral para agrupar erros iguais.")

            # --- Faturamento ---
            with tab3:
                st.subheader("Relatório de faturamento por CClass")

                if not faturamento_itens:
                    st.info("Nenhum item de faturamento encontrado nos XML válidos.")
                else:
                    df_fat = pd.DataFrame(faturamento_itens)

                    df_agg = (
                        df_fat
                        .groupby("cClass")
                        .agg(
                            qtd_itens=("cClass", "count"),
                            total_vServ=("vServ", "sum"),
                            total_vICMS=("vICMS", "sum"),
                            total_vPIS=("vPIS", "sum"),
                            total_vCOFINS=("vCOFINS", "sum"),
                        )
                        .reset_index()
                    )

                    total_geral = df_agg["total_vServ"].sum()
                    if total_geral > 0:
                        df_agg["participacao_vServ_%"] = (df_agg["total_vServ"] / total_geral) * 100

                    st.dataframe(df_agg, use_container_width=True)

                    csv_fat = df_agg.to_csv(index=False).encode("utf-8-sig")
                    st.download_button(
                        "Baixar CSV de faturamento por CClass",
                        data=csv_fat,
                        file_name="faturamento_por_cclass.csv",
                        mime="text/csv"
                    )

    else:
        st.info("Faça o upload dos arquivos XML e clique em 'Validar arquivos' para iniciar a análise.")


if __name__ == "__main__":
    main()
