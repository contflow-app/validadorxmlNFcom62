import io
from typing import List, Dict, Any

import streamlit as st
import pandas as pd
import yaml
from lxml import etree
import re
import zipfile

from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib.utils import simpleSplit

# Caminho do logo da Contare no repositório
LOGO_PATH = "Logo-Contare-ISP-1.png"


# ====================================================
# Namespace NFCom
# ====================================================

def get_ns(tree: etree._ElementTree) -> Dict[str, str]:
    """
    Retorna o namespace padrão do NFCom mapeado como prefixo 'n'.
    """
    root = tree.getroot()
    default_ns = root.nsmap.get(None)
    return {"n": default_ns} if default_ns else {}


# ====================================================
# Configuração
# ====================================================

st.set_page_config(page_title="Validador NFCom 62 - Contare", layout="wide")


# ====================================================
# Leitura de arquivos de configuração
# ====================================================

@st.cache_data
def load_rules(path: str = "rules.yaml") -> List[Dict[str, Any]]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or []
    except FileNotFoundError:
        st.warning(f"Arquivo '{path}' não encontrado.")
        return []


@st.cache_data
def load_cclass_config(path: str = "cclass_config.yaml") -> Dict[str, Any]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except FileNotFoundError:
        st.warning(f"Arquivo '{path}' não encontrado.")
        return {}


# ====================================================
# XML helpers
# ====================================================

def parse_xml(file_bytes: bytes) -> etree._ElementTree:
    try:
        parser = etree.XMLParser(remove_blank_text=True)
        return etree.parse(io.BytesIO(file_bytes), parser)
    except Exception as e:
        raise ValueError(f"XML inválido: {e}")


def get_xpath_nodes(tree: etree._ElementTree, xpath: str):
    ns = get_ns(tree)
    root = tree.getroot()
    if ns:
        return root.xpath(xpath, namespaces=ns)
    return root.xpath(xpath)


def get_nf_model(tree: etree._ElementTree) -> str:
    ns = get_ns(tree)
    root = tree.getroot()
    if ns:
        n = root.xpath(".//n:ide/n:mod", namespaces=ns)
    else:
        n = root.xpath(".//ide/mod")
    return (n[0].text or "").strip() if n else ""


# ====================================================
# Motor de REGRAS (rules.yaml)
# ====================================================

def apply_rule_to_node(rule: Dict[str, Any], node, file_name: str) -> List[Dict[str, Any]]:
    erros = []
    tipo = rule.get("tipo")

    if tipo == "regex":
        txt = (node.text or "").strip()
        pattern = rule.get("parametros", {}).get("pattern", "")
        if pattern and not re.match(pattern, txt):
            erros.append({
                "arquivo": file_name,
                "regra_id": rule.get("id"),
                "descricao_regra": rule.get("descricao"),
                "campo_xpath": rule.get("xpath"),
                "valor_encontrado": txt,
                "mensagem_erro": rule.get("mensagem_erro"),
                "sugestao_correcao": rule.get("sugestao_correcao"),
                "nivel": rule.get("nivel", "erro"),
            })

    elif tipo == "obrigatorio":
        txt = (node.text or "").strip() if node is not None else ""
        if not txt:
            erros.append({
                "arquivo": file_name,
                "regra_id": rule.get("id"),
                "descricao_regra": rule.get("descricao"),
                "campo_xpath": rule.get("xpath"),
                "valor_encontrado": txt,
                "mensagem_erro": rule.get("mensagem_erro"),
                "sugestao_correcao": rule.get("sugestao_correcao"),
                "nivel": rule.get("nivel", "erro"),
            })

    elif tipo == "lista_valores":
        txt = (node.text or "").strip()
        valores_ok = rule.get("parametros", {}).get("valores_permitidos", [])
        if txt not in valores_ok:
            erros.append({
                "arquivo": file_name,
                "regra_id": rule.get("id"),
                "descricao_regra": rule.get("descricao"),
                "campo_xpath": rule.get("xpath"),
                "valor_encontrado": txt,
                "mensagem_erro": rule.get("mensagem_erro"),
                "sugestao_correcao": rule.get("sugestao_correcao"),
                "nivel": "erro",
            })

    return erros


def validate_with_rules_yaml(tree, rules, file_name):
    erros = []
    root = tree.getroot()
    ns = get_ns(tree)

    # Detectar CRT (Simples Nacional = 1; Normal = 3)
    if ns:
        crt_nodes = root.xpath(".//n:emit/n:CRT", namespaces=ns)
    else:
        crt_nodes = root.xpath(".//emit/CRT")
    crt = (crt_nodes[0].text or "").strip() if crt_nodes else ""

    for rule in rules:
        tipo = rule.get("tipo")
        rule_id = rule.get("id")
        xpath = rule.get("xpath", "")
        params = rule.get("parametros", {}) or {}

        # Ignorar regras de PIS/COFINS para SN
        if rule_id in ("R_DET_PIS_VPIS_OBRIG", "R_DET_COFINS_VCOFINS_OBRIG") and crt != "3":
            continue

        if tipo == "condicional":
            if ns:
                base_nodes = root.xpath(xpath, namespaces=ns)
            else:
                base_nodes = root.xpath(xpath)

            for node in base_nodes:
                cond_xpath = params.get("condicao_xpath")
                cond_vals = params.get("condicao_valores", [])
                alvo_xpath = params.get("alvo_xpath")
                alvo_esperado = params.get("alvo_valor_esperado")
                obrig = params.get("alvo_obrigatorio", True)

                if cond_xpath:
                    if ns:
                        cond_nodes = node.xpath(cond_xpath, namespaces=ns)
                    else:
                        cond_nodes = node.xpath(cond_xpath)
                    cond_text = (cond_nodes[0].text or "").strip() if cond_nodes else ""
                else:
                    cond_text = ""

                if cond_vals and cond_text not in cond_vals:
                    continue

                if alvo_xpath:
                    if ns:
                        alvo_nodes = node.xpath(alvo_xpath, namespaces=ns)
                    else:
                        alvo_nodes = node.xpath(alvo_xpath)
                    alvo_text = (alvo_nodes[0].text or "").strip() if alvo_nodes else ""
                else:
                    alvo_text = ""

                erro = False
                if alvo_esperado is not None:
                    if alvo_text != str(alvo_esperado):
                        erro = True
                else:
                    if obrig and not alvo_text:
                        erro = True
                    if not obrig and alvo_text:
                        erro = True

                if erro:
                    erros.append({
                        "arquivo": file_name,
                        "regra_id": rule_id,
                        "descricao_regra": rule.get("descricao"),
                        "campo_xpath": f"{xpath}/{alvo_xpath}",
                        "valor_encontrado": alvo_text,
                        "mensagem_erro": rule.get("mensagem_erro"),
                        "sugestao_correcao": rule.get("sugestao_correcao"),
                        "nivel": rule.get("nivel", "erro"),
                    })

        else:
            nodes = get_xpath_nodes(tree, xpath)
            if not nodes and tipo == "obrigatorio":
                erros.append({
                    "arquivo": file_name,
                    "regra_id": rule_id,
                    "descricao_regra": rule.get("descricao"),
                    "campo_xpath": xpath,
                    "valor_encontrado": "",
                    "mensagem_erro": rule.get("mensagem_erro"),
                    "sugestao_correcao": rule.get("sugestao_correcao"),
                    "nivel": "erro",
                })
            else:
                for node in nodes:
                    erros.extend(apply_rule_to_node(rule, node, file_name))

    return erros


# ====================================================
# Regras customizadas (Python)
# ====================================================

def is_dest_pf_or_pj_nao_contrib(tree):
    root = tree.getroot()
    ns = get_ns(tree)
    dests = root.xpath(".//n:dest", namespaces=ns) if ns else root.xpath(".//dest")
    if not dests:
        return False

    d = dests[0]
    if ns:
        cpf_nodes = d.xpath("./n:CPF", namespaces=ns)
        cnpj_nodes = d.xpath("./n:CNPJ", namespaces=ns)
        ind_nodes = d.xpath("./n:indIEDest", namespaces=ns)
    else:
        cpf_nodes = d.xpath("./CPF")
        cnpj_nodes = d.xpath("./CNPJ")
        ind_nodes = d.xpath("./indIEDest")

    cpf = (cpf_nodes[0].text or "").strip() if cpf_nodes else ""
    cnpj = (cnpj_nodes[0].text or "").strip() if cnpj_nodes else ""
    ind = (ind_nodes[0].text or "").strip() if ind_nodes else ""

    if cpf and (not ind or ind in ("2", "9")):
        return True
    if cnpj and ind == "9":
        return True

    return False


def validate_cfop_pf_pj_nao_contrib(tree, file_name, cclass_cfg):
    erros = []
    if not is_dest_pf_or_pj_nao_contrib(tree):
        return erros

    root = tree.getroot()
    ns = get_ns(tree)
    sva_cclasses = cclass_cfg.get("sva_cclasses", [])

    if ns:
        dets = root.xpath(".//n:det", namespaces=ns)
        uf_e = root.xpath(".//n:emit/n:enderEmit/n:UF", namespaces=ns)
        uf_d = root.xpath(".//n:dest/n:enderDest/n:UF", namespaces=ns)
    else:
        dets = root.xpath(".//det")
        uf_e = root.xpath(".//emit/enderEmit/UF")
        uf_d = root.xpath(".//dest/enderDest/UF")

    uf_emit = (uf_e[0].text or "").strip() if uf_e else ""
    uf_dest = (uf_d[0].text or "").strip() if uf_d else ""

    if uf_emit == uf_dest:
        cfops_ok = ["5307"]
    else:
        cfops_ok = ["6307"]

    for det in dets:
        if ns:
            cclass = det.xpath("./n:prod/n:cClass", namespaces=ns)
            cfop = det.xpath("./n:prod/n:CFOP", namespaces=ns)
        else:
            cclass = det.xpath("./prod/cClass")
            cfop = det.xpath("./prod/CFOP")

        cclass = (cclass[0].text or "").strip() if cclass else ""
        cfop = (cfop[0].text or "").strip() if cfop else ""

        if cclass in sva_cclasses:
            continue
        if not cfop:
            continue
        if cfop not in cfops_ok:
            erros.append({
                "arquivo": file_name,
                "regra_id": "R_CFOP_PF_NCONTRIB",
                "descricao_regra": "PF/PJ não contribuinte deve usar CFOP 5307/6307",
                "campo_xpath": ".//det/prod/CFOP",
                "valor_encontrado": cfop,
                "mensagem_erro": f"CFOP '{cfop}' incompatível.",
                "sugestao_correcao": f"Ajustar CFOP para {cfops_ok}.",
                "nivel": "erro",
            })
    return erros


def validate_sva_cfop_zero(tree, file_name, cclass_cfg):
    erros = []
    sva = cclass_cfg.get("sva_cclasses", [])
    root = tree.getroot()
    ns = get_ns(tree)

    dets = root.xpath(".//n:det", namespaces=ns) if ns else root.xpath(".//det")

    for det in dets:
        if ns:
            cclass = det.xpath("./n:prod/n:cClass", namespaces=ns)
            cfop = det.xpath("./n:prod/n:CFOP", namespaces=ns)
        else:
            cclass = det.xpath("./prod/cClass")
            cfop = det.xpath("./prod/CFOP")

        cclass = (cclass[0].text or "").strip() if cclass else ""
        cfop = (cfop[0].text or "").strip() if cfop else ""

        if cclass not in sva:
            continue

        if not cfop:
            continue

        erros.append({
            "arquivo": file_name,
            "regra_id": "R_SVA_CFOP_ZERO",
            "descricao_regra": "Itens SVA não devem possuir CFOP",
            "campo_xpath": ".//det/prod/CFOP",
            "valor_encontrado": cfop,
            "mensagem_erro": f"CFOP '{cfop}' inválido para SVA",
            "sugestao_correcao": "Remover CFOP de SVAs.",
            "nivel": "erro",
        })
    return erros


def validate_custom_rules(tree, file_name, cclass_cfg):
    erros = []
    erros.extend(validate_cfop_pf_pj_nao_contrib(tree, file_name, cclass_cfg))
    erros.extend(validate_sva_cfop_zero(tree, file_name, cclass_cfg))
    return erros


# ====================================================
# Extração para faturamento por CClass
# ====================================================

def extract_faturamento_items(tree, file_name):
    itens = []
    ns = get_ns(tree)
    root = tree.getroot()

    dets = root.xpath(".//n:det", namespaces=ns) if ns else root.xpath(".//det")

    def to_float(x):
        try:
            return float(str(x).replace(",", ".")) if x else 0.0
        except:
            return 0.0

    for det in dets:
        if ns:
            cclass = det.xpath("./n:prod/n:cClass", namespaces=ns)
            desc = det.xpath("./n:prod/n:xProd", namespaces=ns)
            vprod = det.xpath("./n:prod/n:vProd", namespaces=ns)
        else:
            cclass = det.xpath("./prod/cClass")
            desc = det.xpath("./prod/xProd")
            vprod = det.xpath("./prod/vProd")

        cclass = (cclass[0].text or "").strip() if cclass else ""
        desc = (desc[0].text or "").strip() if desc else ""
        vprod = to_float((vprod[0].text or "").strip()) if vprod else 0.0

        itens.append({
            "arquivo": file_name,
            "cClass": cclass,
            "descricao": desc,
            "vServ": vprod,
        })

    return itens


# ====================================================
# Correção dos XMLs (CFOP de SVA + Paliativo vProd = vItem)
# ====================================================

def generate_corrected_xml(tree, cclass_cfg, corrigir_descontos):
    root = tree.getroot()
    copy_root = etree.fromstring(etree.tostring(root))
    new_tree = etree.ElementTree(copy_root)
    ns = get_ns(new_tree)
    sva = cclass_cfg.get("sva_cclasses", [])

    def to_float(x):
        try:
            return float(str(x).replace(",", ".")) if x else 0.0
        except:
            return 0.0

    dets = copy_root.xpath(".//n:det", namespaces=ns) if ns else copy_root.xpath(".//det")

    for det in dets:

        if ns:
            cclass = det.xpath("./n:prod/n:cClass", namespaces=ns)
            cfop = det.xpath("./n:prod/n:CFOP", namespaces=ns)
        else:
            cclass = det.xpath("./prod/cClass")
            cfop = det.xpath("./prod/CFOP")

        cclass = (cclass[0].text or "").strip() if cclass else ""
        cfop_nodes = cfop

        # Remover CFOP de SVA
        if cclass in sva and cfop_nodes:
            for node in cfop_nodes:
                parent = node.getparent()
                if parent is not None:
                    parent.remove(node)

        # Correção vProd = vItem se desconto
        if corrigir_descontos:
            if ns:
                vitem = det.xpath("./n:prod/n:vItem", namespaces=ns)
                vprod = det.xpath("./n:prod/n:vProd", namespaces=ns)
            else:
                vitem = det.xpath("./prod/vItem")
                vprod = det.xpath("./prod/vProd")

            if vitem and vprod:
                vi = (vitem[0].text or "").strip()
                vp = (vprod[0].text or "").strip()
                vi_f = to_float(vi)
                vp_f = to_float(vp)

                if vp_f < vi_f:
                    vprod[0].text = vi

    return etree.tostring(new_tree, encoding="utf-8", xml_declaration=True)


# ====================================================
# PDF
# ====================================================

def generate_pdf(df: pd.DataFrame, logo_path: str = LOGO_PATH):
    buffer = io.BytesIO()
    c = canvas.Canvas(buffer, pagesize=A4)
    w, h = A4
    x = 40
    y = h - 60

    # Logo
    try:
        c.drawImage(logo_path, x, h - 100, width=90, preserveAspectRatio=True, mask='auto')
        c.setFont("Helvetica-Bold", 14)
        c.drawString(x + 100, h - 60, "Relatório de Erros – NFCom")
        y = h - 120
    except:
        c.setFont("Helvetica-Bold", 14)
        c.drawString(x, h - 60, "Relatório de Erros – NFCom")
        y = h - 100

    c.setFont("Helvetica", 10)

    for _, row in df.iterrows():
        bloco = [
            f"Arquivo: {row['arquivo']}",
            f"Regra: {row['regra_id']} - {row['descricao_regra']}",
            f"XPath: {row['campo_xpath']}",
            f"Valor: {row['valor_encontrado']}",
            f"Erro: {row['mensagem_erro']}",
            f"Sugestão: {row['sugestao_correcao']}",
            "-" * 120
        ]

        for linha in bloco:
            wrap = simpleSplit(linha, "Helvetica", 10, w - 80)
            for l in wrap:
                if y < 70:
                    c.showPage()
                    c.setFont("Helvetica", 10)
                    y = h - 60
                c.drawString(x, y, l)
                y -= 14

    c.setFont("Helvetica-Oblique", 8)
    c.drawString(x, 40, "Desenvolvido por Raul Martins – Contare Contabilidade especializada em Provedores de Internet")

    c.save()
    buffer.seek(0)
    return buffer


# ====================================================
# Interface Streamlit
# ====================================================

def main():
    col1, col2 = st.columns([1, 3])

    with col1:
        try:
            st.image(LOGO_PATH)
        except:
            st.write("")

    with col2:
        st.markdown("<h2>Validador NFCom Modelo 62</h2><p>Contare – Contabilidade especializada em Provedores de Internet</p>", unsafe_allow_html=True)

    st.write("Valide, corrija e gere relatórios completos de NFCom.")

    rules = load_rules()
    cclass_cfg = load_cclass_config()

    st.sidebar.header("Opções")

    consolidar = st.sidebar.checkbox("Consolidar erros iguais", value=True)
    corrigir_descontos = st.sidebar.checkbox("Corrigir descontos (vProd = vItem)", value=False)

    uploaded = st.file_uploader("Selecione arquivos XML", type=["xml"], accept_multiple_files=True)

    if uploaded and st.button("Validar arquivos"):
        erros_total = []
        erros_invalidos = []
        faturamento = []
        xml_corrigidos = []

        for f in uploaded:
            nome = f.name
            try:
                content = f.read()
                tree = parse_xml(content)

                modelo = get_nf_model(tree)
                if modelo and modelo != "62":
                    erros_invalidos.append({"arquivo": nome, "erro": f"Modelo {modelo} não é NFCom"})
                    continue

                # YAML
                erros_total.extend(validate_with_rules_yaml(tree, rules, nome))
                # Custom
                erros_total.extend(validate_custom_rules(tree, nome, cclass_cfg))
                # Faturamento
                faturamento.extend(extract_faturamento_items(tree, nome))

                # XML Corrigido
                corrigido = generate_corrected_xml(tree, cclass_cfg, corrigir_descontos)
                xml_corrigidos.append({"nome": nome.replace(".xml", "_corrigido.xml"), "conteudo": corrigido})

            except ValueError as e:
                erros_invalidos.append({"arquivo": nome, "erro": str(e)})

        if erros_invalidos:
            st.subheader("Arquivos inválidos")
            st.dataframe(pd.DataFrame(erros_invalidos), use_container_width=True)

        # ZIP
        if xml_corrigidos:
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
                for x in xml_corrigidos:
                    z.writestr(x["nome"], x["conteudo"])
            buf.seek(0)
            st.download_button(
                "Baixar XMLs corrigidos",
                data=buf,
                file_name="xml_corrigidos.zip",
                mime="application/zip"
            )

        if not erros_total:
            st.success("Nenhum erro encontrado.")
            return

        df = pd.DataFrame(erros_total)

        tab1, tab2, tab3, tab4 = st.tabs([
            "Erros Detalhados",
            "Erros Consolidados",
            "Faturamento por CClass",
            "Dashboard"
        ])

        with tab1:
            st.subheader("Erros por arquivo")
            st.dataframe(df, use_container_width=True)

            st.download_button("Baixar CSV detalhado", df.to_csv(index=False), "erros_detalhado.csv")

            pdf = generate_pdf(df)
            st.download_button("Baixar PDF", pdf, "erros_nfcom.pdf", mime="application/pdf")

        with tab2:
            if consolidar:
                agrupado = (
                    df.groupby(["regra_id", "descricao_regra", "mensagem_erro", "sugestao_correcao"])
                    .agg(qtd=("arquivo", "count"), arquivos=("arquivo", lambda x: ", ".join(sorted(set(x)))))
                    .reset_index()
                )
                st.dataframe(agrupado, use_container_width=True)
                st.download_button("Baixar CSV consolidado", agrupado.to_csv(index=False), "erros_consolidados.csv")
            else:
                st.info("Marque consolidação na barra lateral.")

        with tab3:
            df_f = pd.DataFrame(faturamento)
            if not df_f.empty:
                out = (
                    df_f.groupby(["cClass", "descricao"])
                    .agg(qtd=("arquivo", "count"), total=("vServ", "sum"))
                    .reset_index()
                )
                st.dataframe(out, use_container_width=True)
                st.download_button("Baixar CSV faturamento", out.to_csv(index=False), "faturamento_cclass.csv")
            else:
                st.info("Nenhum item encontrado.")

        with tab4:
            st.metric("Total erros", len(df))
            st.metric("Arquivos afetados", df["arquivo"].nunique())
            st.metric("Regras acionadas", df["regra_id"].nunique())

            por_regra = df.groupby("regra_id").size()
            st.bar_chart(por_regra)

            por_arquivo = df.groupby("arquivo").size()
            st.bar_chart(por_arquivo)

            por_nivel = df.groupby("nivel").size()
            st.bar_chart(por_nivel)

    st.markdown("<hr><p style='text-align:center;font-size:12px;'>Desenvolvido por Raul Martins – Contare Contabilidade especializada em Provedores de Internet</p>", unsafe_allow_html=True)


if __name__ == "__main__":
    main()
